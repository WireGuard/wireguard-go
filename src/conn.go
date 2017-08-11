package main

import (
	"net"
)

func updateUDPConn(device *Device) error {
	var err error
	netc := &device.net
	netc.mutex.Lock()

	// close existing connection

	if netc.conn != nil {
		netc.conn.Close()
	}

	// open new connection

	if device.tun.isUp.Get() {
		conn, err := net.ListenUDP("udp", netc.addr)
		if err == nil {
			netc.conn = conn
			signalSend(device.signal.newUDPConn)
		}
	}

	netc.mutex.Unlock()
	return err
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
