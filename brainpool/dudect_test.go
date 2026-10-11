// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"crypto/rand"
	"crypto/sha256"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"testing"
	"time"
)

// A statistical timing-leakage check in the manner of dudect (Reparaz,
// Balasch and Verbauwhede, DATE 2017), as in the koblitz package: ECDH
// and signing are timed with a fixed secret scalar and with fresh random
// ones, interleaved in random order, and Welch's t-test compares the two
// timing distributions, whole and cropped at several percentiles. |t|
// above 10 is treated as a leak.

type welch struct{ n, mean, m2 [2]float64 }

func (w *welch) push(class int, x float64) {
	w.n[class]++
	d := x - w.mean[class]
	w.mean[class] += d / w.n[class]
	w.m2[class] += d * (x - w.mean[class])
}

func (w *welch) t() float64 {
	if w.n[0] < 2 || w.n[1] < 2 {
		return 0
	}
	den := math.Sqrt(w.m2[0]/(w.n[0]-1)/w.n[0] + w.m2[1]/(w.n[1]-1)/w.n[1])
	if den == 0 {
		return 0
	}
	return (w.mean[0] - w.mean[1]) / den
}

func leakage(classes []int, times []float64) float64 {
	sorted := append([]float64(nil), times...)
	sort.Float64s(sorted)
	crops := []float64{math.Inf(1)}
	for _, p := range []float64{0.5, 0.7, 0.8, 0.9, 0.95, 0.99} {
		crops = append(crops, sorted[int(p*float64(len(sorted)-1))])
	}
	worst := 0.0
	for _, c := range crops {
		var w welch
		for i, x := range times {
			if x <= c {
				w.push(classes[i], x)
			}
		}
		worst = math.Max(worst, math.Abs(w.t()))
	}
	return worst
}

func measure(n int, prepare func(class int) func(), rng *mrand.Rand) ([]int, []float64) {
	classes := make([]int, 2*n)
	for i := range classes {
		classes[i] = i % 2
	}
	rng.Shuffle(len(classes), func(i, j int) { classes[i], classes[j] = classes[j], classes[i] })
	ops := make([]func(), len(classes))
	for i, c := range classes {
		ops[i] = prepare(c)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	runtime.GC()
	times := make([]float64, len(ops))
	for i, op := range ops {
		start := time.Now()
		op()
		times[i] = float64(time.Since(start).Nanoseconds())
	}
	return classes, times
}

// The detector finds a leak it is shown: a double-and-add that skips the
// addition for zero bits.
func TestDudectDetectorSelfCheck(t *testing.T) {
	c := bp256
	leaky := func(class int) func() {
		k := make([]byte, c.size)
		k[c.size-1] = 1
		if class == 1 {
			k, _, _ = c.randomScalar(rand.Reader)
		}
		return func() {
			acc := c.identity()
			for _, b := range k {
				for i := 7; i >= 0; i-- {
					acc = c.add(acc, acc)
					if b>>uint(i)&1 == 1 {
						acc = c.add(acc, c.gen)
					}
				}
			}
		}
	}
	cl, tm := measure(200, leaky, mrand.New(mrand.NewPCG(1, 2)))
	if tv := leakage(cl, tm); tv < 10 {
		t.Fatalf("the detector missed a data-dependent routine: |t| = %.1f", tv)
	}
}

func TestDudectSecretScalars(t *testing.T) {
	if os.Getenv("SIGMA_DUDECT") == "" {
		t.Skip("long statistical timing test; set SIGMA_DUDECT=1 (and optionally SIGMA_DUDECT_N, measurements per class, default 5000)")
	}
	n := 5000
	if v, err := strconv.Atoi(os.Getenv("SIGMA_DUDECT_N")); err == nil && v > 100 {
		n = v
	}
	digest := sha256.Sum256([]byte("message"))
	for _, c := range []*curve{bp256, bp384, bp512} {
		order := c.params.N
		fixed := map[string]*big.Int{
			"one":           big.NewInt(1),
			"n-1":           new(big.Int).Sub(order, big.NewInt(1)),
			"high bit only": new(big.Int).Lsh(big.NewInt(1), uint(order.BitLen()-2)),
		}
		fr, _, _ := c.randomScalar(rand.Reader)
		fixed["fixed random"] = new(big.Int).SetBytes(fr)
		_, peer, _ := GenerateECDHKey(c, rand.Reader)
		for name, k := range fixed {
			kb := k.FillBytes(make([]byte, c.size))
			for _, op := range []struct {
				what string
				run  func(d []byte)
			}{
				{"ECDH", func(d []byte) { _, _ = ECDH(c, d, peer) }},
				{"Sign", func(d []byte) {
					key, _ := newPrivateKey(c, d)
					_, _ = key.Sign(rand.Reader, digest[:], nil)
				}},
			} {
				prepare := func(class int) func() {
					d := kb
					if class == 1 {
						d, _, _ = c.randomScalar(rand.Reader)
					}
					return func() { op.run(d) }
				}
				cl, tm := measure(n, prepare, mrand.New(mrand.NewPCG(uint64(n), 7)))
				tv := leakage(cl, tm)
				t.Logf("%s %s, fixed %s vs random: max |t| = %.2f over %d measurements", c.params.Name, op.what, name, tv, 2*n)
				if tv > 10 {
					t.Errorf("%s %s: timing depends on the secret (fixed %s vs random, |t| = %.1f)", c.params.Name, op.what, name, tv)
				}
			}
		}
	}
}
