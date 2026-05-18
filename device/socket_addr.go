package device

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IpSocketAddr [20]byte

func (b *IpSocketAddr) Encode(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	b[1] = 0 // reserved

	// port
	binary.BigEndian.PutUint16(b[2:4], uint16(udpAddr.Port))

	ip := udpAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		b[0] = 0x04

		// IPv4 mapped into last 4 bytes
		copy(b[16:20], ip4)
		return nil
	}

	b[0] = 0x06
	copy(b[4:20], ip.To16())

	return nil
}

func (b *IpSocketAddr) Decode() (*net.UDPAddr, error) {
	if b[1] != 0 {
		return nil, fmt.Errorf("reserved byte must be 0")
	}

	port := int(binary.BigEndian.Uint16(b[2:4]))

	switch b[0] {
	case 0x04:
		ip := net.IPv4(b[16], b[17], b[18], b[19])
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}, nil

	case 0x06:
		ip := net.IP(b[4:20])
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}, nil

	default:
		return nil, fmt.Errorf("invalid version: %x", b[0])
	}
}
