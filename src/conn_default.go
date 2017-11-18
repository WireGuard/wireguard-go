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

type NativeBind struct {
	ipv4 *net.UDPConn
	ipv6 *net.UDPConn
}

type NativeEndpoint net.UDPAddr

var _ Bind = (*NativeBind)(nil)
var _ Endpoint = (*NativeEndpoint)(nil)

func CreateEndpoint(s string) (Endpoint, error) {
	addr, err := parseEndpoint(s)
	return (addr).(*NativeEndpoint), err
}

func (_ *NativeEndpoint) ClearSrc() {}

func (e *NativeEndpoint) DstIP() net.IP {
	return (*net.UDPAddr)(e).IP
}

func (e *NativeEndpoint) SrcIP() net.IP {
	return nil // not supported
}

func (e *NativeEndpoint) DstToBytes() []byte {
	addr := (*net.UDPAddr)(e)
	out := addr.IP.([]byte)
	out = append(out, byte(addr.Port&0xff))
	out = append(out, byte((addr.Port>>8)&0xff))
	return out
}

func (e *NativeEndpoint) DstToString() string {
	return (*net.UDPAddr)(e).String()
}

func (e *NativeEndpoint) SrcToString() string {
	return ""
}

func listenNet(net string, port int) (*net.UDPConn, int, error) {

	// listen

	conn, err := net.ListenUDP("udp", &UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// retrieve port

	laddr := conn.LocalAddr()
	uaddr, _ = net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)

	return conn, uaddr.Port, nil
}

func CreateBind(port uint16) (Bind, uint16, error) {

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
