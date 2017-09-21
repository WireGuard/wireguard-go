package main

import (
	"golang.org/x/sys/unix"
	"net"
)

func setMark(conn *net.UDPConn, value uint32) error {
	if conn == nil {
		return nil
	}

	file, err := conn.File()
	if err != nil {
		return err
	}

	return unix.SetsockoptInt(
		int(file.Fd()),
		unix.SOL_SOCKET,
		unix.SO_MARK,
		int(value),
	)
}
