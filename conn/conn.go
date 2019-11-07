/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

// Package conn implements WireGuard's network connections.
package conn

import (
	"errors"
	"net"
	"strings"
)

// A Bind listens on a port for both IPv6 and IPv4 UDP traffic.
type Bind interface {
	// LastMark reports the last mark set for this Bind.
	LastMark() uint32

	// SetMark sets the mark for each packet sent through this Bind.
	// This mark is passed to the kernel as the socket option SO_MARK.
	SetMark(mark uint32) error

	// ReceiveIPv6 reads an IPv6 UDP packet into b.
	//
	// It reports the number of bytes read, n,
	// the packet source address ep,
	// and any error.
	ReceiveIPv6(buff []byte) (n int, ep Endpoint, err error)

	// ReceiveIPv4 reads an IPv4 UDP packet into b.
	//
	// It reports the number of bytes read, n,
	// the packet source address ep,
	// and any error.
	ReceiveIPv4(b []byte) (n int, ep Endpoint, err error)

	// Send writes a packet b to address ep.
	Send(b []byte, ep Endpoint) error

	// Close closes the Bind connection.
	Close() error
}

// CreateBind creates a Bind bound to a port.
//
// The value actualPort reports the actual port number the Bind
// object gets bound to.
func CreateBind(port uint16) (b Bind, actualPort uint16, err error) {
	return createBind(port)
}

// BindToInterface is implemented by Bind objects that support being
// tied to a single network interface.
type BindToInterface interface {
	BindToInterface4(interfaceIndex uint32, blackhole bool) error
	BindToInterface6(interfaceIndex uint32, blackhole bool) error
}

// An Endpoint maintains the source/destination caching for a peer.
//
//	dst : the remote address of a peer ("endpoint" in uapi terminology)
//	src : the local address from which datagrams originate going to the peer
type Endpoint interface {
	ClearSrc()           // clears the source address
	SrcToString() string // returns the local source address (ip:port)
	DstToString() string // returns the destination address (ip:port)
	DstToBytes() []byte  // used for mac2 cookie calculations
	DstIP() net.IP
	SrcIP() net.IP
}

func parseEndpoint(s string) (*net.UDPAddr, error) {
	// ensure that the host is an IP address

	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if i := strings.LastIndexByte(host, '%'); i > 0 && strings.IndexByte(host, ':') >= 0 {
		// Remove the scope, if any. ResolveUDPAddr below will use it, but here we're just
		// trying to make sure with a small sanity test that this is a real IP address and
		// not something that's likely to incur DNS lookups.
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("Failed to parse IP address: " + host)
	}

	// parse address and port

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		addr.IP = ip4
	}
	return addr, err
}
