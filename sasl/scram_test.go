// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl_test

import (
	"errors"
	"testing"

	"github.com/cB-Sigma/iotcrypto/sasl"
)

// The two-step server against the client, both mechanisms (RFC 5802,
// RFC 7677); a wrong password and an unknown mechanism are refused.
//
// Covers: SIG-IPE-3627
func TestScramSteps(t *testing.T) {
	users := func(u string) (string, bool) { return map[string]string{"dev": "pencil"}[u], u == "dev" }
	for _, mech := range []string{sasl.SCRAMSHA256, sasl.SCRAMSHA1} {
		for _, pw := range []string{"pencil", "wrong"} {
			srv, err := sasl.NewScramServer(mech, users)
			if err != nil {
				t.Fatal(err)
			}
			var user string
			err = sasl.Client(mech, "dev", pw, func(msg []byte, last bool) ([]byte, error) {
				if !last {
					return srv.First(msg)
				}
				u, fin, err := srv.Final(msg)
				user = u
				return fin, err
			})
			if ok := err == nil && user == "dev"; ok != (pw == "pencil") {
				t.Errorf("%s with %q: user %q, %v", mech, pw, user, err)
			}
		}
	}
	var e sasl.Error
	if _, err := sasl.NewScramServer("PLAIN", users); !errors.As(err, &e) {
		t.Errorf("PLAIN: %v", err)
	}
}
