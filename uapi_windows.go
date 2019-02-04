/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"github.com/Microsoft/go-winio"
	"net"
)

//TODO: replace these with actual standard windows error numbers from the win package
const (
	ipcErrorIO        = -int64(5)
	ipcErrorProtocol  = -int64(71)
	ipcErrorInvalid   = -int64(22)
	ipcErrorPortInUse = -int64(98)
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

func UAPIListen(name string) (net.Listener, error) {
	config := winio.PipeConfig{
		SecurityDescriptor: "", //TODO: we want this to be a very locked down pipe.
	}
	listener, err := winio.ListenPipe("\\\\.\\pipe\\wireguard\\"+name, &config) //TODO: choose sane name.
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
