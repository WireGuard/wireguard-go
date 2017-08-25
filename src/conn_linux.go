package main

import (
	"golang.org/x/sys/unix"
	"net"
)

func setMark(conn *net.UDPConn, value int) error {
	if conn == nil || value == 0 {
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
		value,
	)
}
