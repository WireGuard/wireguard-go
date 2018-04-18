// +build linux,386

/* Copyright 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

const (
	_SENDMSG = 16
	_RECVMSG = 17
)

func sendmsg(fd int, msghdr *unix.Msghdr, flags int) (uintptr, uintptr, syscall.Errno) {
	args := struct {
		fd     uintptr
		msghdr uintptr
		flags  uintptr
	}{
		uintptr(fd),
		uintptr(unsafe.Pointer(msghdr)),
		uintptr(flags),
	}
	return unix.Syscall(
		unix.SYS_SOCKETCALL,
		_SENDMSG,
		uintptr(unsafe.Pointer(&args)),
		0,
	)
}

func recvmsg(fd int, msghdr *unix.Msghdr, flags int) (uintptr, uintptr, syscall.Errno) {
	args := struct {
		fd     uintptr
		msghdr uintptr
		flags  uintptr
	}{
		uintptr(fd),
		uintptr(unsafe.Pointer(msghdr)),
		uintptr(flags),
	}
	return unix.Syscall(
		unix.SYS_SOCKETCALL,
		_RECVMSG,
		uintptr(unsafe.Pointer(&args)),
		0,
	)
}
