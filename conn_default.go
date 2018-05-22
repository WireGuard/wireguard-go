// +build !linux

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

package main

import (
	"golang.org/x/sys/unix"
	"net"
	"runtime"
)

/* This code is meant to be a temporary solution
 * on platforms for which the sticky socket / source caching behavior
 * has not yet been implemented.
 *
 * See conn_linux.go for an implementation on the linux platform.
 */

type NativeBind struct {
	ipv4 *net.UDPConn
	ipv6 *net.UDPConn
}

type NativeEndpoint net.UDPAddr

var _ Bind = (*NativeBind)(nil)
var _ Endpoint = (*NativeEndpoint)(nil)

func CreateEndpoint(s string) (Endpoint, error) {
	addr, err := parseEndpoint(s)
	return (*NativeEndpoint)(addr), err
}

func (_ *NativeEndpoint) ClearSrc() {}

func (e *NativeEndpoint) DstIP() net.IP {
	return (*net.UDPAddr)(e).IP
}

func (e *NativeEndpoint) SrcIP() net.IP {
	return nil // not supported
}

func (e *NativeEndpoint) DstToBytes() []byte {
	addr := (*net.UDPAddr)(e)
	out := addr.IP.To4()
	if out == nil {
		out = addr.IP
	}
	out = append(out, byte(addr.Port&0xff))
	out = append(out, byte((addr.Port>>8)&0xff))
	return out
}

func (e *NativeEndpoint) DstToString() string {
	return (*net.UDPAddr)(e).String()
}

func (e *NativeEndpoint) SrcToString() string {
	return ""
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {

	// listen

	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// retrieve port

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

func CreateBind(uport uint16, device *Device) (Bind, uint16, error) {
	var err error
	var bind NativeBind

	port := int(uport)

	bind.ipv4, port, err = listenNet("udp4", port)
	if err != nil {
		return nil, 0, err
	}

	bind.ipv6, port, err = listenNet("udp6", port)
	if err != nil {
		bind.ipv4.Close()
		return nil, 0, err
	}

	return &bind, uint16(port), nil
}

func (bind *NativeBind) Close() error {
	err1 := bind.ipv4.Close()
	err2 := bind.ipv6.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (bind *NativeBind) ReceiveIPv4(buff []byte) (int, Endpoint, error) {
	n, endpoint, err := bind.ipv4.ReadFromUDP(buff)
	if endpoint != nil {
		endpoint.IP = endpoint.IP.To4()
	}
	return n, (*NativeEndpoint)(endpoint), err
}

func (bind *NativeBind) ReceiveIPv6(buff []byte) (int, Endpoint, error) {
	n, endpoint, err := bind.ipv6.ReadFromUDP(buff)
	return n, (*NativeEndpoint)(endpoint), err
}

func (bind *NativeBind) Send(buff []byte, endpoint Endpoint) error {
	var err error
	nend := endpoint.(*NativeEndpoint)
	if nend.IP.To4() != nil {
		_, err = bind.ipv4.WriteToUDP(buff, (*net.UDPAddr)(nend))
	} else {
		_, err = bind.ipv6.WriteToUDP(buff, (*net.UDPAddr)(nend))
	}
	return err
}

var fwmarkIoctl int

func init() {
	if runtime.GOOS == "freebsd" {
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	} else if runtime.GOOS == "openbsd" {
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func (bind *NativeBind) SetMark(mark uint32) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	fd4, err1 := bind.ipv4.SyscallConn()
	fd6, err2 := bind.ipv6.SyscallConn()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	err3 := fd4.Control(func(fd uintptr) {
		err1 = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
	})
	err4 := fd6.Control(func(fd uintptr) {
		err2 = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
	})
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	if err3 != nil {
		return err3
	}
	if err4 != nil {
		return err4
	}
	return nil
}
