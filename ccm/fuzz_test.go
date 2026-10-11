// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package ccm

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

// FuzzOpen feeds arbitrary ciphertexts, nonces and parameters to Open. It
// must never panic on a well-sized nonce, and whatever Seal produces must
// open to the same plaintext, while any one-bit change must not.
func FuzzOpen(f *testing.F) {
	f.Add(uint8(13), uint8(8), []byte("header"), []byte("meter reading 42"), []byte{1, 2, 3})
	f.Add(uint8(7), uint8(4), []byte{}, []byte{}, []byte{})
	f.Add(uint8(12), uint8(16), bytes.Repeat([]byte{0xA5}, 300), bytes.Repeat([]byte{0x5A}, 70), []byte{0xff})
	key := bytes.Repeat([]byte{0x40}, 16)
	blk, err := aes.NewCipher(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, nonceSize, tagSize uint8, ad, plain, junk []byte) {
		a, err := New(blk, int(nonceSize), int(tagSize))
		if err != nil {
			return
		}
		nonce := make([]byte, a.NonceSize())
		_, _ = a.Open(nil, nonce, junk, ad) // must not panic
		sealed := a.Seal(nil, nonce, plain, ad)
		got, err := a.Open(nil, nonce, sealed, ad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("round trip: %x, %v", got, err)
		}
		bit := len(junk) % (8 * len(sealed))
		sealed[bit/8] ^= 1 << (bit % 8)
		if _, err := a.Open(nil, nonce, sealed, ad); err == nil {
			t.Fatalf("bit %d flipped and the message still opened", bit)
		}
	})
}

func BenchmarkSeal(b *testing.B) {
	blk, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{64, 1024, 16384} {
		for _, p := range []struct{ nonce, tag int }{{13, 8}, {12, 16}} {
			b.Run(fmt.Sprintf("%dB/nonce%d/tag%d", size, p.nonce, p.tag), func(b *testing.B) {
				a, err := New(blk, p.nonce, p.tag)
				if err != nil {
					b.Fatal(err)
				}
				nonce := make([]byte, p.nonce)
				plain := make([]byte, size)
				out := make([]byte, 0, size+p.tag)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					out = a.Seal(out[:0], nonce, plain, nil)
				}
			})
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	blk, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	a, err := New(blk, 13, 8)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 13)
	sealed := a.Seal(nil, nonce, make([]byte, 1024), nil)
	out := make([]byte, 0, 1024)
	b.SetBytes(1024)
	b.ReportAllocs()
	for b.Loop() {
		var err error
		if out, err = a.Open(out[:0], nonce, sealed, nil); err != nil {
			b.Fatal(err)
		}
	}
}
