// +build !linux

package main

import (
	"net"
)

func SetMark(conn *net.UDPConn, value uint32) error {
	return nil
}
