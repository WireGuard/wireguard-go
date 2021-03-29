/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net"
	"syscall"
)

// StdNetBind is meant to be a temporary solution on platforms for which
// the sticky socket / source caching behavior has not yet been implemented.
// It uses the Go's net package to implement networking.
// See LinuxSocketBind for a proper implementation on the Linux platform.
type StdNetBind struct {
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	blackhole4 bool
	blackhole6 bool
}

func NewStdNetBind() Bind { return &StdNetBind{} }

type StdNetEndpoint net.UDPAddr

var _ Bind = (*StdNetBind)(nil)
var _ Endpoint = (*StdNetEndpoint)(nil)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := parseEndpoint(s)
	return (*StdNetEndpoint)(addr), err
}

func (*StdNetEndpoint) ClearSrc() {}

func (e *StdNetEndpoint) DstIP() net.IP {
	return (*net.UDPAddr)(e).IP
}

func (e *StdNetEndpoint) SrcIP() net.IP {
	return nil // not supported
}

func (e *StdNetEndpoint) DstToBytes() []byte {
	addr := (*net.UDPAddr)(e)
	out := addr.IP.To4()
	if out == nil {
		out = addr.IP
	}
	out = append(out, byte(addr.Port&0xff))
	out = append(out, byte((addr.Port>>8)&0xff))
	return out
}

func (e *StdNetEndpoint) DstToString() string {
	return (*net.UDPAddr)(e).String()
}

func (e *StdNetEndpoint) SrcToString() string {
	return ""
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn, uaddr.Port, nil
}

func (bind *StdNetBind) Open(uport uint16) (uint16, error) {
	var err error
	var tries int

	if bind.ipv4 != nil || bind.ipv6 != nil {
		return 0, ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var ipv4, ipv6 *net.UDPConn

	ipv4, port, err = listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return 0, err
	}

	// Listen on the same port as we're using for ipv4.
	ipv6, port, err = listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		ipv4.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		ipv4.Close()
		return 0, err
	}
	if ipv4 == nil && ipv6 == nil {
		return 0, syscall.EAFNOSUPPORT
	}
	bind.ipv4 = ipv4
	bind.ipv6 = ipv6
	return uint16(port), nil
}

func (bind *StdNetBind) Close() error {
	var err1, err2 error
	if bind.ipv4 != nil {
		err1 = bind.ipv4.Close()
		bind.ipv4 = nil
	}
	if bind.ipv6 != nil {
		err2 = bind.ipv6.Close()
		bind.ipv6 = nil
	}
	bind.blackhole4 = false
	bind.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (bind *StdNetBind) ReceiveIPv4(buff []byte) (int, Endpoint, error) {
	if bind.ipv4 == nil {
		return 0, nil, syscall.EAFNOSUPPORT
	}
	n, endpoint, err := bind.ipv4.ReadFromUDP(buff)
	if endpoint != nil {
		endpoint.IP = endpoint.IP.To4()
	}
	return n, (*StdNetEndpoint)(endpoint), err
}

func (bind *StdNetBind) ReceiveIPv6(buff []byte) (int, Endpoint, error) {
	if bind.ipv6 == nil {
		return 0, nil, syscall.EAFNOSUPPORT
	}
	n, endpoint, err := bind.ipv6.ReadFromUDP(buff)
	return n, (*StdNetEndpoint)(endpoint), err
}

func (bind *StdNetBind) Send(buff []byte, endpoint Endpoint) error {
	var err error
	nend, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	var conn *net.UDPConn
	var blackhole bool
	if nend.IP.To4() != nil {
		blackhole = bind.blackhole4
		conn = bind.ipv4
	} else {
		blackhole = bind.blackhole6
		conn = bind.ipv6
	}
	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	_, err = conn.WriteToUDP(buff, (*net.UDPAddr)(nend))
	return err
}
