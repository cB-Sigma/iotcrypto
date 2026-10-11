// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl_test

import (
	"fmt"

	"github.com/cB-Sigma/iotcrypto/sasl"
)

// A SCRAM-SHA-256 exchange between the client and the two-step server.
func Example() {
	users := func(u string) (string, bool) { return "pencil", u == "user" }
	srv, _ := sasl.NewScramServer(sasl.SCRAMSHA256, users)
	var who string
	err := sasl.Client(sasl.SCRAMSHA256, "user", "pencil", func(msg []byte, last bool) ([]byte, error) {
		if !last {
			return srv.First(msg)
		}
		u, final, err := srv.Final(msg)
		who = u
		return final, err
	})
	fmt.Println(who, err)
	// Output: user <nil>
}
