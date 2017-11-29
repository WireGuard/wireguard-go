package main

import (
	"errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
)

/* A Bind handles listening on a port for both IPv6 and IPv4 UDP traffic
 */
type Bind interface {
	SetMark(value uint32) error
	ReceiveIPv6(buff []byte) (int, Endpoint, error)
	ReceiveIPv4(buff []byte) (int, Endpoint, error)
	Send(buff []byte, end Endpoint) error
	Close() error
}

/* An Endpoint maintains the source/destination caching for a peer
 *
 * dst : the remote address of a peer ("endpoint" in uapi terminology)
 * src : the local address from which datagrams originate going to the peer
 */
type Endpoint interface {
	ClearSrc()           // clears the source address
	SrcToString() string // returns the local source address (ip:port)
	DstToString() string // returns the destination address (ip:port)
	DstToBytes() []byte  // used for mac2 cookie calculations
	DstIP() net.IP
	SrcIP() net.IP
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
func unsafeCloseBind(device *Device) error {
	var err error
	netc := &device.net
	if netc.bind != nil {
		err = netc.bind.Close()
		netc.bind = nil
	}
	return err
}

func updateBind(device *Device) error {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	netc := &device.net
	netc.mutex.Lock()
	defer netc.mutex.Unlock()

	// close existing sockets

	if err := unsafeCloseBind(device); err != nil {
		return err
	}

	// assumption: netc.update WaitGroup should be exactly 1

	// open new sockets

	if device.tun.isUp.Get() {

		device.log.Debug.Println("UDP bind updating")

		// bind to new port

		var err error
		netc.bind, netc.port, err = CreateBind(netc.port)
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
			if peer.endpoint != nil {
				peer.endpoint.ClearSrc()
			}
			peer.mutex.Unlock()
		}

		// decrease waitgroup to 0

		go device.RoutineReceiveIncoming(ipv4.Version, netc.bind)
		go device.RoutineReceiveIncoming(ipv6.Version, netc.bind)

		device.log.Debug.Println("UDP bind has been updated")
	}

	return nil
}

func closeBind(device *Device) error {
	device.mutex.Lock()
	device.net.mutex.Lock()
	err := unsafeCloseBind(device)
	device.net.mutex.Unlock()
	device.mutex.Unlock()
	return err
}
