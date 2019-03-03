/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"math/rand"
	"net"
)

type DummyEndpoint struct {
	src [16]byte
	dst [16]byte
}

func CreateDummyEndpoint() (*DummyEndpoint, error) {
	var end DummyEndpoint
	if _, err := rand.Read(end.src[:]); err != nil {
		return nil, err
	}
	_, err := rand.Read(end.dst[:])
	return &end, err
}

func (e *DummyEndpoint) ClearSrc() {}

func (e *DummyEndpoint) SrcToString() string {
	var addr net.UDPAddr
	addr.IP = e.SrcIP()
	addr.Port = 1000
	return addr.String()
}

func (e *DummyEndpoint) DstToString() string {
	var addr net.UDPAddr
	addr.IP = e.DstIP()
	addr.Port = 1000
	return addr.String()
}

func (e *DummyEndpoint) SrcToBytes() []byte {
	return e.src[:]
}

func (e *DummyEndpoint) DstIP() net.IP {
	return e.dst[:]
}

func (e *DummyEndpoint) SrcIP() net.IP {
	return e.src[:]
}
