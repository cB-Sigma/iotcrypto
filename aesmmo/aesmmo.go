// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package aesmmo implements the Zigbee block-cipher hash: the
// Matyas-Meyer-Oseas construction over AES-128 (Zigbee specification
// 05-3474 Annex B.6, with hashlen = 128), as used for install-code link
// keys (Base Device Behavior 3.1 6.11.1.2) and as the hash of Smart Energy
// certificate-based key establishment (SE 1.4a C.4.2.2.6), and HMAC over
// it (SE 1.4a C.4.2.2.7, block size 16).
//
// Each block is hashed as H_j = E(H_(j-1), M_j) XOR M_j with H_0 = 0: the
// running digest is the AES key. Padding appends a 1 bit, zero bits, and
// the message length in bits: as 16 bits when it is below 2^16 bits, and
// otherwise as 32 bits followed by 16 zero bits, with the zero run chosen
// so the padded message is a whole number of blocks.
package aesmmo

import (
	"crypto/aes"
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// Size and BlockSize are both 16 octets.
const (
	Size      = 16
	BlockSize = 16
)

type digest struct {
	h   [Size]byte
	buf [BlockSize]byte
	nb  int    // octets in buf
	len uint64 // total octets written
}

// New returns a new AES-MMO hash.Hash.
func New() hash.Hash {
	return new(digest)
}

// Sum returns the AES-MMO digest of data.
func Sum(data []byte) [Size]byte {
	var d digest
	d.Write(data)
	var out [Size]byte
	copy(out[:], d.Sum(nil))
	return out
}

// MAC returns HMAC-AES-MMO of msg under key.
func MAC(key, msg []byte) []byte {
	m := hmac.New(New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func (d *digest) Reset()         { *d = digest{} }
func (d *digest) Size() int      { return Size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) block(m []byte) {
	c, err := aes.NewCipher(d.h[:])
	if err != nil {
		panic(err) // a 16-octet key never fails
	}
	var e [BlockSize]byte
	c.Encrypt(e[:], m)
	for i := range e {
		d.h[i] = e[i] ^ m[i]
	}
}

func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	d.len += uint64(n)
	if d.nb > 0 {
		k := copy(d.buf[d.nb:], p)
		d.nb += k
		p = p[k:]
		if d.nb < BlockSize {
			return n, nil
		}
		d.block(d.buf[:])
		d.nb = 0
	}
	for len(p) >= BlockSize {
		d.block(p[:BlockSize])
		p = p[BlockSize:]
	}
	d.nb = copy(d.buf[:], p)
	return n, nil
}

// Sum appends the digest of what was written so far; d is unchanged.
func (d *digest) Sum(in []byte) []byte {
	c := *d
	bits := c.len * 8
	var tail []byte
	if bits < 1<<16 {
		// 1 bit, zeros, 16-bit length: 1 + k + 16 = 0 mod 128 after the message.
		tail = make([]byte, 0, 2*BlockSize)
		tail = append(tail, 0x80)
		for (c.nb+len(tail)+2)%BlockSize != 0 {
			tail = append(tail, 0)
		}
		tail = binary.BigEndian.AppendUint16(tail, uint16(bits))
	} else {
		// 1 bit, zeros, 32-bit length, 16 zero bits.
		tail = make([]byte, 0, 2*BlockSize)
		tail = append(tail, 0x80)
		for (c.nb+len(tail)+6)%BlockSize != 0 {
			tail = append(tail, 0)
		}
		tail = binary.BigEndian.AppendUint32(tail, uint32(bits))
		tail = append(tail, 0, 0)
	}
	c.Write(tail)
	return append(in, c.h[:]...)
}
