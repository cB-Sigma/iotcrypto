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

// SCRAM with channel binding (-PLUS) and a server that keeps salted credentials instead of
// passwords. Over a real connection each side computes the binding from
// its own TLS state, for example sasl.TLSBinding(&conn.ConnectionState());
// here both use the same fixed bytes.
func Example_channelBinding() {
	binding := sasl.ChannelBinding{Type: sasl.TLSExporter, Data: make([]byte, 32)}
	offered := sasl.Mechanisms(true) // what the server announces over TLS
	mech := sasl.Choose(offered, true)

	// Stored once per user and hash, when the password is set.
	salt := []byte("a random salt, 16+ bytes")
	cred, _ := sasl.NewCredentials(mech, "pencil", salt, 10000)

	srv, _ := sasl.NewStoredScramServer(mech, func(u string) (sasl.Credentials, bool) {
		return cred, u == "user"
	}, sasl.Options{ChannelBinding: binding})
	err := sasl.ClientWith(mech, "user", "pencil", sasl.Options{ChannelBinding: binding},
		func(msg []byte, last bool) ([]byte, error) {
			if !last {
				return srv.First(msg)
			}
			_, final, err := srv.Final(msg)
			return final, err
		})
	fmt.Println(mech, err)
	// Output: SCRAM-SHA-512-PLUS <nil>
}
