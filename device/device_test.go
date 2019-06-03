/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

/* Create two device instances and simulate full WireGuard interaction
 * without network dependencies
 */

import (
	"bytes"
	"testing"
)

func TestDevice(t *testing.T) {

	// prepare tun devices for generating traffic

	tun1 := newDummyTUN("tun1")
	tun2 := newDummyTUN("tun2")

	_ = tun1
	_ = tun2

	// prepare endpoints

	end1, err := CreateDummyEndpoint()
	if err != nil {
		t.Error("failed to create endpoint:", err.Error())
	}

	end2, err := CreateDummyEndpoint()
	if err != nil {
		t.Error("failed to create endpoint:", err.Error())
	}

	_ = end1
	_ = end2

	// create binds

}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := newDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, logger)
	device.SetPrivateKey(sk)
	return device
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}
