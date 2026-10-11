// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package aesmmo_test

import (
	"fmt"

	"github.com/cB-Sigma/iotcrypto/aesmmo"
)

// Hash a Zigbee install code with the Matyas-Meyer-Oseas construction over
// AES-128; the result is the 16-byte link key derived from it.
func ExampleSum() {
	installCode := []byte{0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5, 0x05, 0xC3, 0xB5}
	key := aesmmo.Sum(installCode)
	fmt.Printf("%X\n", key)
	// Output:
	// 66B6900981E1EE3CA4206B6B861C02BB
}
