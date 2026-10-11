// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl

import "testing"

// FuzzServer feeds arbitrary client messages to the server, with and
// without channel binding: it must not panic, and must never accept a
// client without the password.
func FuzzServer(f *testing.F) {
	for _, v := range vectors {
		f.Add(v.clientFirst, v.clientFinal, false)
	}
	f.Add("p=tls-exporter,,n=user,r=abc", "c=cD10bHMtZXhwb3J0ZXIsLA==,r=abc,p=AAAA", true)
	f.Add("y,a=user,n=user,r=x", "c=eSws,r=x,p=", true)
	f.Add("n,,n=a=2Cb,r=,", ",,,", false)
	cb := ChannelBinding{Type: TLSExporter, Data: make([]byte, 32)}
	f.Fuzz(func(t *testing.T, first, final string, plus bool) {
		mech, opts := SCRAMSHA256, Options{Iterations: 1}
		if plus {
			mech, opts.ChannelBinding = SCRAMSHA256PLUS, cb
		}
		s, err := NewScramServerWith(mech, pencil, opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.First([]byte(first)); err != nil {
			return
		}
		if _, _, err := s.Final([]byte(final)); err == nil {
			t.Fatalf("accepted %q / %q without the password", first, final)
		}
	})
}

// FuzzClient feeds arbitrary server messages to the client.
func FuzzClient(f *testing.F) {
	for _, v := range vectors {
		f.Add(v.serverFirst, v.serverFinal)
	}
	f.Add("r=abcdef,s=QSXCR+Q6sek8bf92,i=1", "v=")
	f.Add("m=x,r=abc", "e=other-error")
	f.Fuzz(func(t *testing.T, first, final string) {
		_ = ClientWith(SCRAMSHA256, "user", "pencil", Options{MaxIterations: 64}, func(msg []byte, last bool) ([]byte, error) {
			if !last {
				return []byte(first), nil
			}
			return []byte(final), nil
		})
	})
}
