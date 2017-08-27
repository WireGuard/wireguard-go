// +build !linux

package main

import (
	"net"
)

func setMark(conn *net.UDPConn, value int) error {
	return nil
}
