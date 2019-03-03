/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

func (device *Device) PeekLookAtSocketFd4() (fd int, err error) {
	sysconn, err := device.net.bind.(*nativeBind).ipv4.SyscallConn()
	if err != nil {
		return
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return
	}
	return
}

func (device *Device) PeekLookAtSocketFd6() (fd int, err error) {
	sysconn, err := device.net.bind.(*nativeBind).ipv6.SyscallConn()
	if err != nil {
		return
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return
	}
	return
}
