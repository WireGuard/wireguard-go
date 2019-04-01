/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package netshell

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modnetshell = windows.NewLazySystemDLL("netshell.dll")
	procHrRenameConnection = modnetshell.NewProc("HrRenameConnection")
)

func HrRenameConnection(guid *windows.GUID, newName *uint16) (err error) {
	err = procHrRenameConnection.Find()
	if err != nil {
		// Missing from servercore, so we can't presume it's always there.
		return
	}

	ret, _, _ := syscall.Syscall(procHrRenameConnection.Addr(), 2, uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(newName)), 0)
	if ret != 0 {
		err = syscall.Errno(ret)
	}
	return
}
