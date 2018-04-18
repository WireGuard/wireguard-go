// +build linux,!386

/* Copyright 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

func sendmsg(fd int, msghdr *unix.Msghdr, flags int) (uintptr, uintptr, syscall.Errno) {
	return unix.Syscall(
		unix.SYS_SENDMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(msghdr)),
		uintptr(flags),
	)
}

func recvmsg(fd int, msghdr *unix.Msghdr, flags int) (uintptr, uintptr, syscall.Errno) {
	return unix.Syscall(
		unix.SYS_RECVMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(msghdr)),
		uintptr(flags),
	)
}
