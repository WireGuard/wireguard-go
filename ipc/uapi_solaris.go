/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	evPort   *unix.EventPort
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
	err1 := l.evPort.Close()
	err2 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

func UAPIListen(name string, file *os.File) (net.Listener, error) {
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}

	socketPath := sockPath(name)

	uapi.evPort, err = unix.NewEventPort()
	if err != nil {
		return nil, err
	}
	stat, err := os.Lstat(socketPath)
	if err != nil {
		return nil, err
	}
	err = uapi.evPort.AssociatePath(socketPath, stat, unix.FILE_MODIFIED|unix.FILE_ATTRIB|unix.FILE_NOFOLLOW, nil)
	if err != nil {
		return nil, err
	}

	go func(l *UAPIListener) {
		for {
			// start with lstat to avoid race condition
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				l.connErr <- err
				return
			}
			_, perr := l.evPort.GetOne(nil)
			if perr == unix.EINTR {
				// If we were interrupted, resume watching.
				continue
			}
			if perr != nil {
				l.connErr <- perr
				return
			}
		}
	}(uapi)

	// watch for new connections

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
