package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

/* TODO:
 * This code can be improved by using fsnotify once:
 * https://github.com/fsnotify/fsnotify/pull/205
 * Is merged
 */

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
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
	return nil
}

func NewUAPIListener(name string) (net.Listener, error) {

	// open UNIX socket

	socketPath := fmt.Sprintf("/var/run/wireguard/%s.sock", name)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	// watch for deletion of socket

	go func(l *UAPIListener) {
		for ; ; time.Sleep(time.Second) {
			if _, err := os.Stat(socketPath); os.IsNotExist(err) {
				l.connErr <- err
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
