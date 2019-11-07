/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
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

	if iface, ok := device.net.bind.(conn.BindToInterface); ok {
		return iface.BindToInterface4(interfaceIndex, blackhole)
	}
	return nil
}

// TODO(crawshaw): this method is a compatibility shim. Replace with direct use of conn.
func (device *Device) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	if device.net.bind == nil {
		return errors.New("Bind is not yet initialized")
	}

	if iface, ok := device.net.bind.(conn.BindToInterface); ok {
		return iface.BindToInterface6(interfaceIndex, blackhole)
	}
	return nil
}
