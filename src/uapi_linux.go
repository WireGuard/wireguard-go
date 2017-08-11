package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path"
)

const (
	ipcErrorIO         = -int64(unix.EIO)
	ipcErrorNotDefined = -int64(unix.ENODEV)
	ipcErrorProtocol   = -int64(unix.EPROTO)
	ipcErrorInvalid    = -int64(unix.EINVAL)
	socketDirectory    = "/var/run/wireguard"
	socketName         = "%s.sock"
)

/* TODO:
 * This code can be improved by using fsnotify once:
 * https://github.com/fsnotify/fsnotify/pull/205
 * Is merged
 */

type UAPIListener struct {
	listener  net.Listener // unix socket listener
	connNew   chan net.Conn
	connErr   chan error
	inotifyFd int
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
	err1 := unix.Close(l.inotifyFd)
	err2 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (l *UAPIListener) Addr() net.Addr {
	return nil
}

func connectUnixSocket(path string) (net.Listener, error) {

	// attempt inital connection

	listener, err := net.Listen("unix", path)
	if err == nil {
		return listener, nil
	}

	// check if active

	_, err = net.Dial("unix", path)
	if err == nil {
		return nil, errors.New("Unix socket in use")
	}

	// attempt cleanup

	err = os.Remove(path)
	if err != nil {
		return nil, err
	}

	return net.Listen("unix", path)
}

func NewUAPIListener(name string) (net.Listener, error) {

	// check if path exist

	err := os.MkdirAll(socketDirectory, 077)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	// open UNIX socket

	socketPath := path.Join(
		socketDirectory,
		fmt.Sprintf(socketName, name),
	)

	listener, err := connectUnixSocket(socketPath)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	// watch for deletion of socket

	uapi.inotifyFd, err = unix.InotifyInit()
	if err != nil {
		return nil, err
	}

	_, err = unix.InotifyAddWatch(
		uapi.inotifyFd,
		socketPath,
		unix.IN_ATTRIB|
			unix.IN_DELETE|
			unix.IN_DELETE_SELF,
	)

	if err != nil {
		return nil, err
	}

	go func(l *UAPIListener) {
		var buff [4096]byte
		for {
			unix.Read(uapi.inotifyFd, buff[:])
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
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
