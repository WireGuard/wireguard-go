// +build linux darwin freebsd openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
)

var socketDirectory = "/var/run/wireguard"

func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", socketDirectory, iface)
}

func UAPIOpen(name string) (*os.File, error) {
	if err := os.MkdirAll(socketDirectory, 0755); err != nil {
		return nil, err
	}

	socketPath := sockPath(name)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	oldUmask := unix.Umask(0077)
	defer unix.Umask(oldUmask)

	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener.File()
	}

	// Test socket, if not in use cleanup and try again.
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}
