package main

import (
	"errors"
	"net"
	"time"
)

func parseEndpoint(s string) (*net.UDPAddr, error) {

	// ensure that the host is an IP address

	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("Failed to parse IP address: " + host)
	}

	// parse address and port

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return addr, err
}

func updateUDPConn(device *Device) error {
	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	// close existing connection

	if netc.conn != nil {
		netc.conn.Close()
		netc.conn = nil

		// We need for that fd to be closed in all other go routines, which
		// means we have to wait. TODO: find less horrible way of doing this.
		time.Sleep(time.Second / 2)
	}

	// open new connection

	if device.tun.isUp.Get() {

		// listen on new address

		conn, err := net.ListenUDP("udp", netc.addr)
		if err != nil {
			return err
		}

		// set fwmark

		err = SetMark(netc.conn, netc.fwmark)
		if err != nil {
			return err
		}

		// retrieve port (may have been chosen by kernel)

		addr := conn.LocalAddr()
		netc.conn = conn
		netc.addr, _ = net.ResolveUDPAddr(
			addr.Network(),
			addr.String(),
		)

		// notify goroutines

		signalSend(device.signal.newUDPConn)
	}

	return nil
}

func closeUDPConn(device *Device) {
	netc := &device.net
	netc.mutex.Lock()
	if netc.conn != nil {
		netc.conn.Close()
	}
	netc.mutex.Unlock()
	signalSend(device.signal.newUDPConn)
}
