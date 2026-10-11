// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package bigmod_test

import (
	"fmt"

	"github.com/cB-Sigma/iotcrypto/bigmod"
)

// Constant-time modular exponentiation: 3^5 mod 13.
func ExampleNat_Exp() {
	m, err := bigmod.NewModulus([]byte{13})
	if err != nil {
		panic(err)
	}
	x, _ := bigmod.NewNat().SetBytes([]byte{3}, m)
	y := bigmod.NewNat().Exp(x, []byte{5}, m)
	fmt.Println(y.Bytes(m))
	// Output:
	// [9]
}
