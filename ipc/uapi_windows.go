/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"github.com/Microsoft/go-winio"
	"net"
)

//TODO: replace these with actual standard windows error numbers from the win package
const (
	IpcErrorIO        = -int64(5)
	IpcErrorProtocol  = -int64(71)
	IpcErrorInvalid   = -int64(22)
	IpcErrorPortInUse = -int64(98)
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	kqueueFd int
	keventFd int
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil

		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	return l.listener.Close()
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

func GetSystemSecurityDescriptor() string {
	//
	// SDDL encoded.
	//
	// (system = SECURITY_NT_AUTHORITY | SECURITY_LOCAL_SYSTEM_RID)
	// owner: system
	// grant: GENERIC_ALL to system
	//
	return "O:SYD:(A;;GA;;;SY)"
}

func UAPIListen(name string) (net.Listener, error) {
	config := winio.PipeConfig{
		SecurityDescriptor: GetSystemSecurityDescriptor(),
	}
	listener, err := winio.ListenPipe("\\\\.\\pipe\\WireGuard\\"+name, &config)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn
		}
	}(uapi)

	return uapi, nil
}
