/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import "errors"

func (device *Device) PeekLookAtSocketFd4() (fd int, err error) {
	nb, ok := device.net.bind.(*nativeBind)
	if !ok {
		return 0, errors.New("no socket exists")
	}
	sysconn, err := nb.ipv4.SyscallConn()
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
	nb, ok := device.net.bind.(*nativeBind)
	if !ok {
		return 0, errors.New("no socket exists")
	}
	sysconn, err := nb.ipv6.SyscallConn()
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
