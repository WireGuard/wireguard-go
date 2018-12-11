// +build android openbsd freebsd

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"golang.org/x/sys/unix"
	"runtime"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func (bind *NativeBind) SetMark(mark uint32) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	if bind.ipv4 != nil {
		fd, err := bind.ipv4.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err != nil {
			return err
		}
	}
	if bind.ipv6 != nil {
		fd, err := bind.ipv6.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err != nil {
			return err
		}
	}
	return nil
}
