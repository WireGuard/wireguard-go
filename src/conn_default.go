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
	return (*NativeEndpoint)(addr), err
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
	out := addr.IP
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

func listenNet(network string, port int) (*net.UDPConn, int, error) {

	// listen

	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// retrieve port

	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn, uaddr.Port, nil
}

func CreateBind(uport uint16) (Bind, uint16, error) {
	var err error
	var bind NativeBind

	port := int(uport)

	bind.ipv4, port, err = listenNet("udp4", port)
	if err != nil {
		return nil, 0, err
	}

	bind.ipv6, port, err = listenNet("udp6", port)
	if err != nil {
		bind.ipv4.Close()
		return nil, 0, err
	}

	return &bind, uint16(port), nil
}

func (bind *NativeBind) Close() error {
	err1 := bind.ipv4.Close()
	err2 := bind.ipv6.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (bind *NativeBind) ReceiveIPv4(buff []byte) (int, Endpoint, error) {
	n, endpoint, err := bind.ipv4.ReadFromUDP(buff)
	return n, (*NativeEndpoint)(endpoint), err
}

func (bind *NativeBind) ReceiveIPv6(buff []byte) (int, Endpoint, error) {
	n, endpoint, err := bind.ipv6.ReadFromUDP(buff)
	return n, (*NativeEndpoint)(endpoint), err
}

func (bind *NativeBind) Send(buff []byte, endpoint Endpoint) error {
	var err error
	nend := endpoint.(*NativeEndpoint)
	if nend.IP.To16() != nil {
		_, err = bind.ipv6.WriteToUDP(buff, (*net.UDPAddr)(nend))
	} else {
		_, err = bind.ipv4.WriteToUDP(buff, (*net.UDPAddr)(nend))
	}
	return err
}

func (bind *NativeBind) SetMark(_ uint32) error {
	return nil
}
