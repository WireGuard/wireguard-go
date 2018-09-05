/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

/* Create two device instances and simulate full WireGuard interaction
 * without network dependencies
 */

import "testing"

func TestDevice(t *testing.T) {

	// prepare tun devices for generating traffic

	tun1, err := CreateDummyTUN("tun1")
	if err != nil {
		t.Error("failed to create tun:", err.Error())
	}

	tun2, err := CreateDummyTUN("tun2")
	if err != nil {
		t.Error("failed to create tun:", err.Error())
	}

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
