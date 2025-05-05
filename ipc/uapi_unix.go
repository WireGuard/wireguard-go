//go:build linux || darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

// socketDirectory is variable because it is modified by a linker
// flag in wireguard-android.
var socketDirectory = "/var/run/wireguard"

const NET_EXT_APP_ID = "com.wireguard.macos.network-extension"

func sockDir() string {
	baseDir := socketDirectory
	homeDir, err := os.UserHomeDir()
	if err == nil && strings.Contains(homeDir, NET_EXT_APP_ID) {
		// this is a macOS sandboxed app, so we don't have access to /var/run
		baseDir = homeDir
	}
	return baseDir
}

func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", sockDir(), iface)
}

func UAPIOpen(name string) (*os.File, error) {
	if err := os.MkdirAll(sockDir(), 0o755); err != nil {
		return nil, err
	}

	socketPath := sockPath(name)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	oldUmask := unix.Umask(0o077)
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
