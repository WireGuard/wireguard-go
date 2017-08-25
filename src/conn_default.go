// +build !linux

package main

import (
	"net"
)

func setFwmark(conn *net.UDPConn, value int) error {
	return nil
}
