package main

import (
	"errors"
	"net"
)

type UDPBind interface {
	SetMark(value uint32) error
	ReceiveIPv6(buff []byte, end *Endpoint) (int, error)
	ReceiveIPv4(buff []byte, end *Endpoint) (int, error)
	Send(buff []byte, end *Endpoint) error
	Close() error
}

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

func UpdateUDPListener(device *Device) error {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	// close existing sockets

	if netc.bind != nil {
		if err := netc.bind.Close(); err != nil {
			return err
		}
	}

	// open new sockets

	if device.tun.isUp.Get() {

		// bind to new port

		var err error
		netc.bind, netc.port, err = CreateUDPBind(netc.port)
		if err != nil {
			return err
		}

		// set mark

		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}

		// clear cached source addresses

		for _, peer := range device.peers {
			peer.mutex.Lock()
			peer.endpoint.value.ClearSrc()
			peer.mutex.Unlock()
		}
	}

	return nil
}

func CloseUDPListener(device *Device) error {
	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()
	return netc.bind.Close()
}
