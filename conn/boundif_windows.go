/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sockoptIP_UNICAST_IF   = 31
	sockoptIPV6_UNICAST_IF = 31
)

func (bind *StdNetBind) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	/* MSDN says for IPv4 this needs to be in net byte order, so that it's like an IP address with leading zeros. */
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, interfaceIndex)
	interfaceIndex = *(*uint32)(unsafe.Pointer(&bytes[0]))

	sysconn, err := bind.ipv4.SyscallConn()
	if err != nil {
		return err
	}
	err2 := sysconn.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, sockoptIP_UNICAST_IF, int(interfaceIndex))
	})
	if err2 != nil {
		return err2
	}
	if err != nil {
		return err
	}
	bind.blackhole4 = blackhole
	return nil
}

func (bind *StdNetBind) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	sysconn, err := bind.ipv6.SyscallConn()
	if err != nil {
		return err
	}
	err2 := sysconn.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, sockoptIPV6_UNICAST_IF, int(interfaceIndex))
	})
	if err2 != nil {
		return err2
	}
	if err != nil {
		return err
	}
	bind.blackhole6 = blackhole
	return nil
}
