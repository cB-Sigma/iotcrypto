// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package koblitz

import (
	"crypto/rand"
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
// Balasch and Verbauwhede, "Dude, is my code constant time?", DATE 2017):
// the scalar multiplication is timed on two classes of secret scalars, a
// fixed one and fresh random ones, interleaved in random order, and
// Welch's t-test compares the two timing distributions, whole and cropped
// at several upper percentiles to drop interrupts and preemptions. A
// constant-time routine keeps |t| small however many measurements are
// taken; dudect treats |t| above 10 as a definite leak, and so do we.

// welch accumulates two classes online (Welford) and gives Welch's t.
type welch struct {
	n    [2]float64
	mean [2]float64
	m2   [2]float64
}

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
	v0 := w.m2[0] / (w.n[0] - 1)
	v1 := w.m2[1] / (w.n[1] - 1)
	den := math.Sqrt(v0/w.n[0] + v1/w.n[1])
	if den == 0 {
		return 0
	}
	return (w.mean[0] - w.mean[1]) / den
}

// leakage returns the largest |t| over the uncropped measurements and
// those below each crop percentile of all measurements.
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

// measure times op on n inputs of each class (prepared beforehand, in a
// random order) and returns the classes and durations in nanoseconds.
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

// The detector itself finds a leak it is shown: a routine whose running
// time grows with the scalar's Hamming weight gives a large |t| on the
// same class split, while two classes of the constant-time ladder with
// random scalars on both sides stay near zero.
//
// Covers: SIG-IPE-2974
func TestDudectDetectorSelfCheck(t *testing.T) {
	c := Sect163k1()
	rng := mrand.New(mrand.NewPCG(1, 2))
	one, _ := c.ScalarFromBytes([]byte{1})
	leaky := func(class int) func() {
		k := one
		if class == 1 {
			k, _ = c.RandomScalar(rand.Reader)
		}
		kb := k.Bytes()
		return func() {
			// A double-and-add that skips the addition for zero bits.
			acc := Infinity()
			for _, b := range kb {
				for i := 7; i >= 0; i-- {
					acc = c.Double(acc)
					if b>>uint(i)&1 == 1 {
						acc = c.Add(acc, c.Generator())
					}
				}
			}
			_ = acc
		}
	}
	cl, tm := measure(300, leaky, rng)
	if tv := leakage(cl, tm); tv < 10 {
		t.Fatalf("the detector missed a data-dependent routine: |t| = %.1f", tv)
	}
}

// Covers: SIG-IPE-2974
func TestDudectScalarMult(t *testing.T) {
	if os.Getenv("SIGMA_DUDECT") == "" {
		t.Skip("long statistical timing test; set SIGMA_DUDECT=1 (and optionally SIGMA_DUDECT_N, measurements per class, default 20000)")
	}
	n := 20000
	if v, err := strconv.Atoi(os.Getenv("SIGMA_DUDECT_N")); err == nil && v > 100 {
		n = v
	}
	for _, c := range []*Curve{Sect163k1(), Sect283k1()} {
		order := new(big.Int).SetBytes(c.Order())
		fixed := map[string]*big.Int{
			"one":           big.NewInt(1),
			"high bit only": new(big.Int).Lsh(big.NewInt(1), uint(c.OrderBits()-2)),
			"n-1":           new(big.Int).Sub(order, big.NewInt(1)),
			"all ones":      new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(c.OrderBits()-1)), big.NewInt(1)),
		}
		fr, _ := c.RandomScalar(rand.Reader)
		fixed["fixed random"] = new(big.Int).SetBytes(fr.Bytes())
		base, _ := c.RandomScalar(rand.Reader)
		point := c.ScalarBaseMult(base)
		for name, k := range fixed {
			kb := make([]byte, c.ScalarSize())
			k.FillBytes(kb)
			ks, err := c.ScalarFromBytes(kb)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []struct {
				what string
				run  func(*Scalar)
			}{
				{"ScalarBaseMult", func(s *Scalar) { c.ScalarBaseMult(s) }},
				{"ScalarMult", func(s *Scalar) { _, _ = c.ScalarMult(point, s) }},
			} {
				prepare := func(class int) func() {
					s := ks
					if class == 1 {
						s, _ = c.RandomScalar(rand.Reader)
					}
					return func() { op.run(s) }
				}
				cl, tm := measure(n, prepare, mrand.New(mrand.NewPCG(uint64(n), 7)))
				tv := leakage(cl, tm)
				t.Logf("%s %s, fixed %s vs random: max |t| = %.2f over %d measurements", c.Name(), op.what, name, tv, 2*n)
				if tv > 10 {
					t.Errorf("%s %s: timing depends on the scalar (fixed %s vs random, |t| = %.1f)", c.Name(), op.what, name, tv)
				}
			}
		}
	}
}
