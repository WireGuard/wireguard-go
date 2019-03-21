/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"golang.org/x/sys/unix"
)

func (device *Device) BindSocketToInterface4(interfaceIndex uint32) error {
	sysconn, err := device.net.bind.(*nativeBind).ipv4.SyscallConn()
	if err != nil {
		return nil
	}
	err2 := sysconn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(interfaceIndex))
	})
	if err2 != nil {
		return err2
	}
	if err != nil {
		return err
	}
	return nil
}

func (device *Device) BindSocketToInterface6(interfaceIndex uint32) error {
	sysconn, err := device.net.bind.(*nativeBind).ipv4.SyscallConn()
	if err != nil {
		return nil
	}
	err2 := sysconn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(interfaceIndex))
	})
	if err2 != nil {
		return err2
	}
	if err != nil {
		return err
	}
	return nil
}
