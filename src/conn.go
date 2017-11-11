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

/* Must hold device and net lock
 */
func unsafeCloseUDPListener(device *Device) error {
	var err error
	netc := &device.net
	if netc.bind != nil {
		err = netc.bind.Close()
		netc.bind = nil
		netc.update.Add(1)
	}
	return err
}

// must inform all listeners
func UpdateUDPListener(device *Device) error {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	// close existing sockets

	if err := unsafeCloseUDPListener(device); err != nil {
		return err
	}

	// assumption: netc.update WaitGroup should be exactly 1

	// open new sockets

	if device.tun.isUp.Get() {

		// bind to new port

		var err error
		netc.bind, netc.port, err = CreateUDPBind(netc.port)
		if err != nil {
			netc.bind = nil
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

		// decrease waitgroup to 0

		device.log.Debug.Println("UDP bind has been updated")
		netc.update.Done()
	}

	return nil
}

func CloseUDPListener(device *Device) error {
	device.mutex.Lock()
	device.net.mutex.Lock()
	err := unsafeCloseUDPListener(device)
	device.net.mutex.Unlock()
	device.mutex.Unlock()
	return err
}
