package main

import (
	"errors"
	"net"
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

func ListenerClose(l *Listener) (err error) {
	if l.active {
		err = CloseIPv4Socket(l.sock)
		l.active = false
	}
	return
}

func (l *Listener) Init() {
	l.update = make(chan struct{}, 1)
	ListenerClose(l)
}

func ListeningUpdate(device *Device) error {
	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	// close existing sockets

	if err := ListenerClose(&netc.ipv4); err != nil {
		return err
	}

	if err := ListenerClose(&netc.ipv6); err != nil {
		return err
	}

	// open new sockets

	if device.tun.isUp.Get() {

		// listen on IPv4

		{
			list := &netc.ipv6
			sock, port, err := CreateIPv4Socket(netc.port)
			if err != nil {
				return err
			}
			netc.port = port
			list.sock = sock
			list.active = true

			if err := SetMark(list.sock, netc.fwmark); err != nil {
				ListenerClose(list)
				return err
			}
			signalSend(list.update)
		}

		// listen on IPv6

		{
			list := &netc.ipv6
			sock, port, err := CreateIPv6Socket(netc.port)
			if err != nil {
				return err
			}
			netc.port = port
			list.sock = sock
			list.active = true

			if err := SetMark(list.sock, netc.fwmark); err != nil {
				ListenerClose(list)
				return err
			}
			signalSend(list.update)
		}

		// TODO: clear endpoint caches
	}

	return nil
}

func ListeningClose(device *Device) error {
	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	if err := ListenerClose(&netc.ipv4); err != nil {
		return err
	}
	signalSend(netc.ipv4.update)

	if err := ListenerClose(&netc.ipv6); err != nil {
		return err
	}
	signalSend(netc.ipv6.update)

	return nil
}
