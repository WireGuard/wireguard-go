package conn

import (
	"errors"
	"net"
	"runtime"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (bind *StdNetBind) OpenOnLocalhost(uport uint16) (recvFns []ReceiveFunc, selectedPort uint16, err error) {
	return bind.OpenOnAddr(net.IPv4(127, 0, 0, 1), net.IPv6loopback, uport)
}

func (s *StdNetBind) OpenOnAddr(ipv4addr net.IP, ipv6addr net.IP, uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn
	var v4pc *ipv4.PacketConn
	var v6pc *ipv6.PacketConn

	v4conn, port, err = listenNet("udp4", ipv4addr, port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	v6conn, port, err = listenNet("udp6", ipv6addr, port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}
	var fns []ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.ipv4PC = v4pc
		}
		fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload))
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
			s.ipv6PC = v6pc
		}
		fns = append(fns, s.makeReceiveIPv6(v6pc, v6conn, s.ipv6RxOffload))
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}
