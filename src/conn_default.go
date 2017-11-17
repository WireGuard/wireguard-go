// +build !linux

package main

import (
	"net"
)

/* This code is meant to be a temporary solution
 * on platforms for which the sticky socket / source caching behavior
 * has not yet been implemented.
 *
 * See conn_linux.go for an implementation on the linux platform.
 */

type Endpoint *net.UDPAddr

type NativeBind *net.UDPConn

func CreateUDPBind(port uint16) (UDPBind, uint16, error) {

	// listen

	addr := UDPAddr{
		Port: int(port),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, 0, err
	}

	// retrieve port

	laddr := conn.LocalAddr()
	uaddr, _ = net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	return uaddr.Port
}

func (_ Endpoint) ClearSrc() {}

func SetMark(conn *net.UDPConn, value uint32) error {
	return nil
}
