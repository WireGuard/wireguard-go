package tun

import (
	"encoding/binary"
	"math/bits"
)

// IP protocol constants
const (
	ProtocolICMP4 = 1
	ProtocolTCP   = 6
	ProtocolUDP   = 17
	ProtocolICMP6 = 58
)

const (
	IPv4SrcAddrOffset = 12
	IPv6SrcAddrOffset = 8
)

var (
	// PseudoHeaderProtocolTCP TCP protocol field of the TCP pseudoheader
	PseudoHeaderProtocolTCP = []byte{0, ProtocolTCP}
	// PseudoHeaderProtocolUDP UDP protocol field of the UDP pseudoheader
	PseudoHeaderProtocolUDP = []byte{0, ProtocolUDP}
	// PseudoHeaderProtocolMap provides dispatch for IP protocol to the corresponding protocol pseudo-header field
	PseudoHeaderProtocolMap = map[uint8][]byte{
		ProtocolTCP: PseudoHeaderProtocolTCP,
		ProtocolUDP: PseudoHeaderProtocolUDP,
	}
)

// ChecksumNoFold performs intermediate checksum computation per RFC 1071
func ChecksumNoFold(b []byte, initial uint64) uint64 {
	// TODO: Explore SIMD and/or other assembly optimizations.
	tmp := make([]byte, 8)
	binary.NativeEndian.PutUint64(tmp, initial)
	ac := binary.BigEndian.Uint64(tmp)
	var carry uint64

	for len(b) >= 128 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[32:40]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[40:48]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[48:56]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[56:64]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[64:72]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[72:80]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[80:88]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[88:96]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[96:104]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[104:112]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[112:120]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[120:128]), carry)
		ac += carry
		b = b[128:]
	}
	if len(b) >= 64 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[32:40]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[40:48]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[48:56]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[56:64]), carry)
		ac += carry
		b = b[64:]
	}
	if len(b) >= 32 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac += carry
		b = b[32:]
	}
	if len(b) >= 16 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac += carry
		b = b[16:]
	}
	if len(b) >= 8 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac += carry
		b = b[8:]
	}
	if len(b) >= 4 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint32(b[:4])), 0)
		ac += carry
		b = b[4:]
	}
	if len(b) >= 2 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint16(b[:2])), 0)
		ac += carry
		b = b[2:]
	}
	if len(b) == 1 {
		tmp := binary.NativeEndian.Uint16([]byte{b[0], 0})
		ac, carry = bits.Add64(ac, uint64(tmp), 0)
		ac += carry
	}

	binary.NativeEndian.PutUint64(tmp, ac)
	return binary.BigEndian.Uint64(tmp)
}

// Checksum performs final checksum computation per RFC 1071
func Checksum(b []byte, initial uint64) uint16 {
	ac := ChecksumNoFold(b, initial)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	return uint16(ac)
}

// PseudoHeaderChecksumNoFold performs intermediate checksum computation for TCP/UDP pseudoheader values
func PseudoHeaderChecksumNoFold(protocol, srcDstAddr, totalLen []byte) uint64 {
	sum := ChecksumNoFold(srcDstAddr, 0)
	sum = ChecksumNoFold(protocol, sum)
	return ChecksumNoFold(totalLen, sum)
}

// ComputeIPChecksum updates IP and TCP/UDP checksums
func ComputeIPChecksum(pkt []byte) {
	ComputeIPChecksumBuffer(pkt, false)
}

// ComputeIPChecksumBuffer updates IP and TCP/UDP checksums using the provided length buffer of size 2
func ComputeIPChecksumBuffer(pkt []byte, partial bool) {
	var (
		lenbuf    [2]byte
		addrsum   uint64
		protocol  uint8
		headerLen int
		totalLen  uint16
	)

	if pkt[0]>>4 == 4 {
		pkt[10], pkt[11] = 0, 0 // clear IP header checksum
		protocol = pkt[9]
		ihl := pkt[0] & 0xF
		headerLen = int(ihl * 4)
		totalLen = binary.BigEndian.Uint16(pkt[2:])
		addrsum = ChecksumNoFold(pkt[IPv4SrcAddrOffset:IPv4SrcAddrOffset+8], 0)
		binary.BigEndian.PutUint16(pkt[10:], ^Checksum(pkt[:IPv4SrcAddrOffset], addrsum))
	} else {
		protocol = pkt[6]
		headerLen = 40
		totalLen = 40 + binary.BigEndian.Uint16(pkt[4:])
		addrsum = ChecksumNoFold(pkt[IPv6SrcAddrOffset:IPv6SrcAddrOffset+32], 0)
	}

	switch protocol {
	case ProtocolTCP:
		pkt[headerLen+16], pkt[headerLen+17] = 0, 0
		binary.BigEndian.PutUint16(lenbuf[:], totalLen-uint16(headerLen))
		tcpCSum := ChecksumNoFold(PseudoHeaderProtocolTCP, addrsum)
		tcpCSum = ChecksumNoFold(lenbuf[:], tcpCSum)
		if partial {
			binary.BigEndian.PutUint16(pkt[headerLen+16:], Checksum([]byte{}, tcpCSum))
		} else {
			binary.BigEndian.PutUint16(pkt[headerLen+16:], ^Checksum(pkt[headerLen:totalLen], tcpCSum))
		}
	case ProtocolUDP:
		pkt[headerLen+6], pkt[headerLen+7] = 0, 0
		binary.BigEndian.PutUint16(lenbuf[:], totalLen-uint16(headerLen))
		udpCSum := ChecksumNoFold(PseudoHeaderProtocolUDP, addrsum)
		udpCSum = ChecksumNoFold(lenbuf[:], udpCSum)
		if partial {
			binary.BigEndian.PutUint16(pkt[headerLen+6:], Checksum([]byte{}, udpCSum))
		} else {
			binary.BigEndian.PutUint16(pkt[headerLen+6:], ^Checksum(pkt[headerLen:totalLen], udpCSum))
		}
	case ProtocolICMP4, ProtocolICMP6:
		pkt[headerLen+2], pkt[headerLen+3] = 0, 0
		binary.BigEndian.PutUint16(pkt[headerLen+2:], ^Checksum(pkt[headerLen:totalLen], 0))
	}
}
