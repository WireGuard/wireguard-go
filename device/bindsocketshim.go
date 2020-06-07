/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"

	"golang.zx2c4.com/wireguard/conn"
)

// TODO(crawshaw): this method is a compatibility shim. Replace with direct use of conn.
func (device *Device) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	if device.net.bind == nil {
		return errors.New("Bind is not yet initialized")
	}

	if iface, ok := device.net.bind.(conn.BindSocketToInterface); ok {
		return iface.BindSocketToInterface4(interfaceIndex, blackhole)
	}
	return nil
}

// TODO(crawshaw): this method is a compatibility shim. Replace with direct use of conn.
func (device *Device) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	if device.net.bind == nil {
		return errors.New("Bind is not yet initialized")
	}

	if iface, ok := device.net.bind.(conn.BindSocketToInterface); ok {
		return iface.BindSocketToInterface6(interfaceIndex, blackhole)
	}
	return nil
}

// TODO(crawshaw): this method is a compatibility shim. Replace with direct use of conn.
func (device *Device) PeekLookAtSocketFd4() (fd int, err error) {
	if device.net.bind == nil {
		return -1, errors.New("Bind is not yet initialized")
	}

	if iface, ok := device.net.bind.(conn.PeekLookAtSocketFd); ok {
		return iface.PeekLookAtSocketFd4()
	}
	return -1, errors.New("unimplemented")
}

// TODO(crawshaw): this method is a compatibility shim. Replace with direct use of conn.
func (device *Device) PeekLookAtSocketFd6() (fd int, err error) {
	if device.net.bind == nil {
		return -1, errors.New("Bind is not yet initialized")
	}

	if iface, ok := device.net.bind.(conn.PeekLookAtSocketFd); ok {
		return iface.PeekLookAtSocketFd6()
	}
	return -1, errors.New("unimplemented")
}
