// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package koblitz

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	mrand "math/rand/v2"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func curves() []*Curve { return []*Curve{Sect163k1(), Sect283k1()} }

// ---------------------------------------------------------------------------
// Field arithmetic against a bit-serial reference on math/big

func polyMulRef(a, b *big.Int) *big.Int {
	r := new(big.Int)
	for i := 0; i < b.BitLen(); i++ {
		if b.Bit(i) == 1 {
			r.Xor(r, new(big.Int).Lsh(a, uint(i)))
		}
	}
	return r
}

func polyModRef(a *big.Int, f *field) *big.Int {
	poly := new(big.Int).SetBit(new(big.Int), f.m, 1)
	for _, k := range f.taps {
		poly.SetBit(poly, k, 1)
	}
	r := new(big.Int).Set(a)
	for r.BitLen() > f.m {
		r.Xor(r, new(big.Int).Lsh(poly, uint(r.BitLen()-1-f.m)))
	}
	return r
}

func feToBig(a *fe) *big.Int {
	r := new(big.Int)
	for i := maxWords - 1; i >= 0; i-- {
		r.Lsh(r, 64)
		r.Or(r, new(big.Int).SetUint64(a[i]))
	}
	return r
}

func randFe(f *field, r *mrand.Rand) fe {
	var a fe
	for i := 0; i < f.words; i++ {
		a[i] = r.Uint64()
	}
	a[f.m/64] &= 1<<uint(f.m%64) - 1
	return a
}

// Covers: SIG-IPE-2750
func TestClmulMatchesReference(t *testing.T) {
	r := mrand.New(mrand.NewPCG(1, 2))
	edge := []uint64{0, 1, ^uint64(0), 1 << 63, 0x8000000000000001, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA}
	check := func(x, y uint64) {
		hi, lo := clmul(x, y)
		want := polyMulRef(new(big.Int).SetUint64(x), new(big.Int).SetUint64(y))
		got := new(big.Int).Lsh(new(big.Int).SetUint64(hi), 64)
		got.Or(got, new(big.Int).SetUint64(lo))
		if got.Cmp(want) != 0 {
			t.Fatalf("clmul(%x, %x) = %x, want %x", x, y, got, want)
		}
	}
	for _, x := range edge {
		for _, y := range edge {
			check(x, y)
		}
	}
	for range 20000 {
		check(r.Uint64(), r.Uint64())
	}
}

// Covers: SIG-IPE-2750
func TestFieldArithmetic(t *testing.T) {
	r := mrand.New(mrand.NewPCG(3, 4))
	for _, c := range curves() {
		f := &c.f
		for range 300 {
			a, b := randFe(f, r), randFe(f, r)
			var z fe
			f.mul(&z, &a, &b)
			want := polyModRef(polyMulRef(feToBig(&a), feToBig(&b)), f)
			if feToBig(&z).Cmp(want) != 0 {
				t.Fatalf("%s: mul mismatch", c.name)
			}
			var s, s2 fe
			f.sqr(&s, &a)
			f.mul(&s2, &a, &a)
			if s != s2 {
				t.Fatalf("%s: sqr != mul(a,a)", c.name)
			}
			if isZero(&a) == 0 {
				var ai, one fe
				f.inv(&ai, &a)
				f.mul(&one, &ai, &a)
				if one != (fe{1}) {
					t.Fatalf("%s: a * a^-1 != 1", c.name)
				}
			}
			// half trace solves z^2 + z = beta when Tr(beta) = 0
			if f.trace(&a) == 0 {
				h := f.halfTrace(&a)
				var h2 fe
				f.sqr(&h2, &h)
				f.add(&h2, &h2, &h)
				if h2 != a {
					t.Fatalf("%s: half trace", c.name)
				}
			}
			enc := f.bytesOf(&a)
			var back fe
			if !f.setBytes(&back, enc) || back != a {
				t.Fatalf("%s: byte round trip", c.name)
			}
		}
		var zero, zi fe
		f.inv(&zi, &zero)
		if zi != zero {
			t.Fatalf("%s: inv(0) != 0", c.name)
		}
		// an encoding with a bit at degree m or above is refused
		bad := make([]byte, f.bytes)
		bad[0] = 0x80
		var x fe
		if f.setBytes(&x, bad) {
			t.Fatalf("%s: out-of-range element accepted", c.name)
		}
	}
}

func TestConstantTimeHelpers(t *testing.T) {
	a, b := fe{1, 2, 3, 4, 5}, fe{6, 7, 8, 9, 10}
	x, y := a, b
	cswap(&x, &y, 0)
	if x != a || y != b {
		t.Fatal("cswap(0) swapped")
	}
	cswap(&x, &y, 1)
	if x != b || y != a {
		t.Fatal("cswap(1) did not swap")
	}
	var z fe
	csel(&z, &a, &b, 0)
	if z != a {
		t.Fatal("csel(0)")
	}
	csel(&z, &a, &b, 1)
	if z != b {
		t.Fatal("csel(1)")
	}
	if isZero(&fe{}) != 1 || isZero(&fe{0, 0, 0, 0, 1 << 63}) != 0 || equal(&a, &a) != 1 || equal(&a, &b) != 0 {
		t.Fatal("isZero/equal")
	}
}

// ---------------------------------------------------------------------------
// Curve parameters (SEC 2)

// Covers: SIG-IPE-2750
func TestSEC2Parameters(t *testing.T) {
	cases := []struct {
		c                     *Curve
		gCompressed           string
		scalar, point, fieldB int
		h                     int
	}{
		{Sect163k1(), "0302FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8", 21, 22, 21, 2},
		{Sect283k1(), "020503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836", 36, 37, 36, 4},
	}
	for _, tc := range cases {
		c := tc.c
		got, err := c.Compress(c.Generator())
		if err != nil || !bytes.Equal(got, unhex(t, tc.gCompressed)) {
			t.Errorf("%s: compressed G = %x", c.name, got)
		}
		p, err := c.DecodePoint(unhex(t, tc.gCompressed))
		if err != nil || !p.Equal(c.Generator()) {
			t.Errorf("%s: decompressed G differs: %v", c.name, err)
		}
		if c.ScalarSize() != tc.scalar || c.PointSize() != tc.point || c.FieldSize() != tc.fieldB || c.Cofactor() != tc.h {
			t.Errorf("%s: sizes %d %d %d %d", c.name, c.ScalarSize(), c.PointSize(), c.FieldSize(), c.Cofactor())
		}
		if !c.InSubgroup(c.Generator()) {
			t.Errorf("%s: n*G != O", c.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Known answers

// Key pairs: the SE 1.4a annex C.5.1 and C.6.1 device keys, the C.5.3 and
// C.6.3 ephemeral keys, and pairs generated by LibreSSL 3.3.6
// (openssl ecparam -genkey), each d with its compressed d*G.
//
// Covers: SIG-IPE-2750
func TestScalarBaseMultKnownAnswers(t *testing.T) {
	cases := []struct {
		c      *Curve
		d, pub string
	}{
		// SE 1.4a C.5.1.2, C.5.1.3 (suite 1 device keys)
		{Sect163k1(), "00b8a900fcadebabbfa383b540fce9ed438395eaa7", "030290a1f5c08dad5f2945e335620c7a98fac46666a1"},
		{Sect163k1(), "01E9DDB5580CF72ECE7F215F0AE594E48DF3E7FEE8", "03025BBA38D0C7B5436B68DF728F093E7A1D6C437E6D"},
		// SE 1.4a C.5.3.3.1, C.5.3.4.1 (suite 1 ephemeral keys)
		{Sect163k1(), "0013D36DE4B1EA8E22739C381370823F404BFF8862", "0300E117C86D0E7CD128B2F34E9076CFF24AF46D7288"},
		{Sect163k1(), "03D48C7210DDBCC4FB2E5E7A0AA16A0DB89540820B", "0306AB52062201D995B8B8591F3F086A3A2E214D845E"},
		// SE 1.4a C.6.1.2, C.6.1.3 (suite 2 device keys)
		{Sect283k1(), "0151CD0DBCB80474BF7AC9FEEBE39C7A32A63518938FCA9754AAE132BC9C73BE94A7E1BE", "0202F4FA2A3040433C6820299D182A1042E41404E337C57F47716B42DFAF970F1580A04C9B"},
		{Sect283k1(), "00F2561ADB39EF49C1D62EF5186C6E0C158A5A45BFCE38660931ACC3694592D5ACDE9006", "03030E56F7ADE866E76372764BA20A9FF1FE4CAE522F94839E70F2ADFC1CA3E97F4DDCAF2E"},
		// SE 1.4a C.6.3.3.1, C.6.3.4.1 (suite 2 ephemeral keys)
		{Sect283k1(), "0013D36DE4B1EA8E22739C381370823F404BFF8862B521FECA9871FB3691846D361304B4", "0305F3394E15680660EECAA36788D9B6F312B971CE2C9617570BF7DFCD21C972017762C332"},
		{Sect283k1(), "03D48C7210DDBCC4FB2E5E7A0AA16A0DB89540820B8DC091AB521EA824AFE117CADE995B", "03009A5131CF5B92A016378C0F7F284ECD47F94010F875D43BF1E9A65474ADBFC63696A930"},
		// LibreSSL 3.3.6
		{Sect163k1(), "013040b381679ac9b4ddded5e52dd30fa269d7e31b", "03038550c3785520d009de9f70bb78437316e23338bb"},
		{Sect163k1(), "02a0317d3caaf3a2d8011e7e32e707ac7b1ef1fb77", "02006a7fd4929f6a6e89594623c8329ba28106725a5c"},
		{Sect283k1(), "00a1ef8f0f297246ba2987d39c012809834638f5a2e7937d10a5db1ea005d44e73d922f3", "03030f603633704468d43f1f41dc2b7828179f3e8b9e75a18102c3ee837ad333394114c890"},
		{Sect283k1(), "0161055a48179da4f425d7b724d972167089a8c0d02fd41a535375ed484e10e11dd2b0e6", "0206658f4dabbcf2c819f0d019a8469686fc4d580ef33409c77fe0b296a429c67eb165eae3"},
	}
	for i, tc := range cases {
		// The C.6.3.4.1 key is above n (F-1500): reduce it, as its public
		// key shows the vector's authors did.
		d := scalarInt(tc.c, new(big.Int).SetBytes(unhex(t, tc.d)))
		q := tc.c.ScalarBaseMult(d)
		got, _ := tc.c.Compress(q)
		if !bytes.Equal(got, unhex(t, tc.pub)) {
			t.Errorf("%d %s: d*G = %x, want %s", i, tc.c.name, got, strings.ToLower(tc.pub))
		}
		p, err := tc.c.DecodePoint(unhex(t, tc.pub))
		if err != nil || !p.Equal(q) || !tc.c.InSubgroup(p) {
			t.Errorf("%d: decode of known public key: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Group law properties

func scalarInt(c *Curve, k *big.Int) *Scalar {
	b := make([]byte, c.ScalarSize())
	new(big.Int).Mod(k, new(big.Int).SetBytes(c.nb)).FillBytes(b)
	s, err := c.ScalarFromBytes(b)
	if err != nil {
		panic(err)
	}
	return s
}

// Covers: SIG-IPE-2750
func TestGroupLaw(t *testing.T) {
	for _, c := range curves() {
		n := new(big.Int).SetBytes(c.nb)
		g := c.Generator()
		one := scalarInt(c, big.NewInt(1))
		if !c.ScalarBaseMult(one).Equal(g) {
			t.Fatalf("%s: 1*G != G", c.name)
		}
		if !c.ScalarBaseMult(scalarInt(c, big.NewInt(2))).Equal(c.Double(g)) {
			t.Fatalf("%s: 2*G != G+G", c.name)
		}
		if !c.ScalarBaseMult(scalarInt(c, big.NewInt(3))).Equal(c.Add(c.Double(g), g)) {
			t.Fatalf("%s: 3*G", c.name)
		}
		nm1 := new(big.Int).Sub(n, big.NewInt(1))
		if !c.ScalarBaseMult(scalarInt(c, nm1)).Equal(c.Neg(g)) {
			t.Fatalf("%s: (n-1)*G != -G", c.name)
		}
		if !c.ScalarBaseMult(c.NewScalar()).IsInfinity() {
			t.Fatalf("%s: 0*G != O", c.name)
		}
		if !c.MulPublic(g, n).IsInfinity() {
			t.Fatalf("%s: MulPublic(n) != O", c.name)
		}
		if !c.Add(g, c.Neg(g)).IsInfinity() {
			t.Fatalf("%s: G + -G != O", c.name)
		}
		for range 8 {
			k1, _ := c.RandomScalar(rand.Reader)
			k2, _ := c.RandomScalar(rand.Reader)
			p1 := c.ScalarBaseMult(k1)
			p2 := c.ScalarBaseMult(k2)
			if !c.IsOnCurve(p1) || !c.InSubgroup(p1) {
				t.Fatalf("%s: k*G off the subgroup", c.name)
			}
			// (k1 + k2) G = k1 G + k2 G
			if !c.ScalarBaseMult(c.AddScalars(k1, k2)).Equal(c.Add(p1, p2)) {
				t.Fatalf("%s: distributivity", c.name)
			}
			// k1 (k2 G) = (k1 k2) G = k2 (k1 G)
			a, _ := c.ScalarMult(p2, k1)
			b, _ := c.ScalarMult(p1, k2)
			if !a.Equal(b) || !a.Equal(c.ScalarBaseMult(c.MulScalars(k1, k2))) {
				t.Fatalf("%s: associativity", c.name)
			}
			// the public ladder agrees
			if !c.MulPublic(p1, new(big.Int).SetBytes(k2.Bytes())).Equal(b) {
				t.Fatalf("%s: MulPublic", c.name)
			}
			// addition commutes and is associative
			p3 := c.Double(p1)
			if !c.Add(p1, p2).Equal(c.Add(p2, p1)) || !c.Add(c.Add(p1, p2), p3).Equal(c.Add(p1, c.Add(p2, p3))) {
				t.Fatalf("%s: addition laws", c.name)
			}
			// compression round trip, both parities appear over the runs
			enc, _ := c.Compress(p1)
			back, err := c.DecodePoint(enc)
			if err != nil || !back.Equal(p1) {
				t.Fatalf("%s: compression round trip: %v", c.name, err)
			}
			unc, _ := c.Uncompressed(p1)
			back, err = c.DecodePoint(unc)
			if err != nil || !back.Equal(p1) {
				t.Fatalf("%s: uncompressed round trip: %v", c.name, err)
			}
		}
	}
}

// A point of the curve outside the order-n subgroup (G plus a point of
// order 2) is on the curve but fails InSubgroup, and h times it is back in.
func TestSubgroupCheck(t *testing.T) {
	for _, c := range curves() {
		t2 := &Point{x: fe{}, y: fe{1}} // (0, 1): order 2
		if !c.IsOnCurve(t2) || c.InSubgroup(t2) || !c.Double(t2).IsInfinity() {
			t.Fatalf("%s: order-2 point", c.name)
		}
		p := c.Add(c.Generator(), t2)
		if !c.IsOnCurve(p) || c.InSubgroup(p) {
			t.Fatalf("%s: G + T2 reported in subgroup", c.name)
		}
		if !c.InSubgroup(c.MulCofactor(p)) {
			t.Fatalf("%s: h(G + T2) not in subgroup", c.name)
		}
		if _, err := c.ScalarMult(t2, scalarInt(c, big.NewInt(5))); err == nil {
			t.Fatalf("%s: scalar mult of an order-2 point accepted", c.name)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range curves() {
		fb := c.FieldSize()
		for _, b := range [][]byte{
			nil,
			{0},
			make([]byte, 1+fb),                     // prefix 00 with a body
			append([]byte{5}, make([]byte, fb)...), // bad prefix
			append([]byte{2}, make([]byte, fb-1)...),
			append([]byte{2, 0xFF}, make([]byte, fb-1)...), // x too large
		} {
			if _, err := c.DecodePoint(b); err == nil {
				t.Errorf("%s: accepted %x", c.name, b)
			}
		}
		// Half of all x values have no point; find one and check it is refused.
		r := mrand.New(mrand.NewPCG(5, 6))
		refused := false
		for range 64 {
			x := randFe(&c.f, r)
			enc := append([]byte{2}, c.f.bytesOf(&x)...)
			if _, err := c.DecodePoint(enc); err != nil {
				refused = true
				break
			}
		}
		if !refused {
			t.Errorf("%s: every random x decoded", c.name)
		}
		// An uncompressed point off the curve.
		g, _ := c.Uncompressed(c.Generator())
		g[len(g)-1] ^= 1
		if _, err := c.DecodePoint(g); err == nil {
			t.Errorf("%s: off-curve point accepted", c.name)
		}
	}
}

func TestScalars(t *testing.T) {
	for _, c := range curves() {
		if _, err := c.ScalarFromBytes(c.Order()); err == nil {
			t.Errorf("%s: n accepted as a scalar", c.name)
		}
		if _, err := c.ScalarFromBytes(make([]byte, c.ScalarSize()+1)); err == nil {
			t.Errorf("%s: long scalar accepted", c.name)
		}
		// Hn keeps floor(log2 n) leftmost bits of a long hash.
		h := bytes.Repeat([]byte{0xFF}, 64)
		e := c.ScalarFromHash(h)
		want := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(c.OrderBits()-1)), big.NewInt(1))
		if new(big.Int).SetBytes(e.Bytes()).Cmp(want) != 0 {
			t.Errorf("%s: Hn of a long hash", c.name)
		}
		// A short hash is used whole.
		e = c.ScalarFromHash([]byte{0x12, 0x34})
		if new(big.Int).SetBytes(e.Bytes()).Int64() != 0x1234 {
			t.Errorf("%s: Hn of a short hash", c.name)
		}
		// Scalar multiplication by the zero scalar and by n-1 at the ladder edge.
		p := c.ScalarBaseMult(scalarInt(c, big.NewInt(7)))
		nm1 := new(big.Int).Sub(new(big.Int).SetBytes(c.nb), big.NewInt(1))
		q, _ := c.ScalarMult(p, scalarInt(c, nm1))
		if !q.Equal(c.Neg(p)) {
			t.Errorf("%s: (n-1)P != -P", c.name)
		}
		z, _ := c.ScalarMult(p, c.NewScalar())
		if !z.IsInfinity() {
			t.Errorf("%s: 0*P != O", c.name)
		}
	}
}

func BenchmarkScalarMult(b *testing.B) {
	for _, c := range curves() {
		k, _ := c.RandomScalar(rand.Reader)
		p := c.ScalarBaseMult(k)
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_, _ = c.ScalarMult(p, k)
			}
		})
	}
}

func BenchmarkFieldMul(b *testing.B) {
	for _, c := range curves() {
		r := mrand.New(mrand.NewPCG(7, 8))
		x, y := randFe(&c.f, r), randFe(&c.f, r)
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				c.f.mul(&x, &x, &y)
			}
		})
	}
}

// BenchmarkScalarMultByWeight times the ladder for scalars of very
// different shape (1, a single high bit, all ones below n, random). It is
// an informal check, not a statistical timing test: the times should agree
// within noise, since the ladder does the same work for every scalar.
func BenchmarkScalarMultByWeight(b *testing.B) {
	for _, c := range curves() {
		n := new(big.Int).SetBytes(c.nb)
		high := new(big.Int).Lsh(big.NewInt(1), uint(c.nBits-2))
		ones := new(big.Int).Sub(high, big.NewInt(1))
		rnd, _ := c.RandomScalar(rand.Reader)
		p := c.ScalarBaseMult(rnd)
		for _, k := range []struct {
			name string
			v    *big.Int
		}{{"one", big.NewInt(1)}, {"highbit", high}, {"ones", ones}, {"nminus1", new(big.Int).Sub(n, big.NewInt(1))}, {"random", new(big.Int).SetBytes(rnd.Bytes())}} {
			s := scalarInt(c, k.v)
			b.Run(c.name+"/"+k.name, func(b *testing.B) {
				for b.Loop() {
					_, _ = c.ScalarMult(p, s)
				}
			})
		}
	}
}
