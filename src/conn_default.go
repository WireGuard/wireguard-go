// +build !linux

package main

import (
	"net"
)

func setMark(conn *net.UDPConn, value uint32) error {
	return nil
}
