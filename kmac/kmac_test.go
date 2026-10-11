// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package kmac

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// The six KMAC samples NIST publishes for SP 800-185 (KMAC_samples):
// key 0x40..0x5F, data 00 01 02 03 or 0x00..0xC7, with and without the
// customization string "My Tagged Application".
// Covers: SIG-IPE-2913
func TestNISTSamples(t *testing.T) {
	key := unhex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	tag := []byte("My Tagged Application")
	for _, c := range []struct {
		name   string
		k256   bool
		x, s   []byte
		n      int
		expect string
	}{
		{"sample 1", false, seq(4), nil, 32, "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"},
		{"sample 2", false, seq(4), tag, 32, "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"},
		{"sample 3", false, seq(200), tag, 32, "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"},
		{"sample 4", true, seq(4), tag, 64, "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"},
		{"sample 5", true, seq(200), nil, 64, "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"},
		{"sample 6", true, seq(200), tag, 64, "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"},
	} {
		var got []byte
		if c.k256 {
			got = Sum256(key, c.x, c.n, c.s)
		} else {
			got = Sum128(key, c.x, c.n, c.s)
		}
		if !bytes.Equal(got, unhex(c.expect)) {
			t.Errorf("%s = %X", c.name, got)
		}
	}
}

// Streaming writes, Sum without disturbing the state, and Reset.
func TestStreaming(t *testing.T) {
	k := []byte("key")
	m := New256(k, 32, nil)
	m.Write([]byte("ab"))
	first := m.Sum(nil)
	m.Write([]byte("c"))
	if !bytes.Equal(m.Sum(nil), Sum256(k, []byte("abc"), 32, nil)) || !bytes.Equal(first, Sum256(k, []byte("ab"), 32, nil)) {
		t.Error("streaming differs from one-shot")
	}
	m.Reset()
	if !bytes.Equal(m.Sum(nil), Sum256(k, nil, 32, nil)) {
		t.Error("reset")
	}
	if !bytes.Equal(rightEncode(0), []byte{0, 1}) || !bytes.Equal(leftEncode(256), []byte{2, 1, 0}) {
		t.Error("encodings")
	}
}
