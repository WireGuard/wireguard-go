package main

import (
	"net"
)

func updateUDPConn(device *Device) error {
	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	// close existing connection

	if netc.conn != nil {
		netc.conn.Close()
	}

	// open new connection

	if device.tun.isUp.Get() {

		// listen on new address

		conn, err := net.ListenUDP("udp", netc.addr)
		if err != nil {
			return err
		}

		// retrieve port (may have been chosen by kernel)

		addr := conn.LocalAddr()
		netc.conn = conn
		netc.addr, _ = net.ResolveUDPAddr(addr.Network(), addr.String())
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
