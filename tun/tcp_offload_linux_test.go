/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"net/netip"
	"testing"

	"github.com/zeronetworks/zn-wireguard-go/conn"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	offset = virtioNetHdrLen
)

var (
	ip4PortA = netip.MustParseAddrPort("192.0.2.1:1")
	ip4PortB = netip.MustParseAddrPort("192.0.2.2:1")
	ip4PortC = netip.MustParseAddrPort("192.0.2.3:1")
	ip6PortA = netip.MustParseAddrPort("[2001:db8::1]:1")
	ip6PortB = netip.MustParseAddrPort("[2001:db8::2]:1")
	ip6PortC = netip.MustParseAddrPort("[2001:db8::3]:1")
)

func tcp4PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32, ipFn func(*header.IPv4Fields)) []byte {
	totalLen := 40 + segmentSize
	b := make([]byte, offset+int(totalLen), 65535)
	ipv4H := header.IPv4(b[offset:])
	srcAs4 := srcIPPort.Addr().As4()
	dstAs4 := dstIPPort.Addr().As4()
	ipFields := &header.IPv4Fields{
		SrcAddr:     tcpip.Address(srcAs4[:]),
		DstAddr:     tcpip.Address(dstAs4[:]),
		Protocol:    unix.IPPROTO_TCP,
		TTL:         64,
		TotalLength: uint16(totalLen),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv4H.Encode(ipFields)
	tcpH := header.TCP(b[offset+20:])
	tcpH.Encode(&header.TCPFields{
		SrcPort:    srcIPPort.Port(),
		DstPort:    dstIPPort.Port(),
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: 20,
		Flags:      flags,
		WindowSize: 3000,
	})
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(20+segmentSize))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	return b
}

func tcp4Packet(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32) []byte {
	return tcp4PacketMutateIPFields(srcIPPort, dstIPPort, flags, segmentSize, seq, nil)
}

func tcp6PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32, ipFn func(*header.IPv6Fields)) []byte {
	totalLen := 60 + segmentSize
	b := make([]byte, offset+int(totalLen), 65535)
	ipv6H := header.IPv6(b[offset:])
	srcAs16 := srcIPPort.Addr().As16()
	dstAs16 := dstIPPort.Addr().As16()
	ipFields := &header.IPv6Fields{
		SrcAddr:           tcpip.Address(srcAs16[:]),
		DstAddr:           tcpip.Address(dstAs16[:]),
		TransportProtocol: unix.IPPROTO_TCP,
		HopLimit:          64,
		PayloadLength:     uint16(segmentSize + 20),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv6H.Encode(ipFields)
	tcpH := header.TCP(b[offset+40:])
	tcpH.Encode(&header.TCPFields{
		SrcPort:    srcIPPort.Port(),
		DstPort:    dstIPPort.Port(),
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: 20,
		Flags:      flags,
		WindowSize: 3000,
	})
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(20+segmentSize))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	return b
}

func tcp6Packet(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32) []byte {
	return tcp6PacketMutateIPFields(srcIPPort, dstIPPort, flags, segmentSize, seq, nil)
}

func Test_handleVirtioRead(t *testing.T) {
	tests := []struct {
		name     string
		hdr      virtioNetHdr
		pktIn    []byte
		wantLens []int
		wantErr  bool
	}{
		{
			"tcp4",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_TCPV4,
				gsoSize:    100,
				hdrLen:     40,
				csumStart:  20,
				csumOffset: 16,
			},
			tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 200, 1),
			[]int{140, 140},
			false,
		},
		{
			"tcp6",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_TCPV6,
				gsoSize:    100,
				hdrLen:     60,
				csumStart:  40,
				csumOffset: 16,
			},
			tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 200, 1),
			[]int{160, 160},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([][]byte, conn.IdealBatchSize)
			sizes := make([]int, conn.IdealBatchSize)
			for i := range out {
				out[i] = make([]byte, 65535)
			}
			tt.hdr.encode(tt.pktIn)
			n, err := handleVirtioRead(tt.pktIn, out, sizes, offset)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("got err: %v", err)
			}
			if n != len(tt.wantLens) {
				t.Fatalf("got %d packets, wanted %d", n, len(tt.wantLens))
			}
			for i := range tt.wantLens {
				if tt.wantLens[i] != sizes[i] {
					t.Fatalf("wantLens[%d]: %d != outSizes: %d", i, tt.wantLens[i], sizes[i])
				}
			}
		})
	}
}

func flipTCP4Checksum(b []byte) []byte {
	at := virtioNetHdrLen + 20 + 16 // 20 byte ipv4 header; tcp csum offset is 16
	b[at] ^= 0xFF
	b[at+1] ^= 0xFF
	return b
}

func Fuzz_handleGRO(f *testing.F) {
	pkt0 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)
	pkt1 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101)
	pkt2 := tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201)
	pkt3 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1)
	pkt4 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101)
	pkt5 := tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201)
	f.Add(pkt0, pkt1, pkt2, pkt3, pkt4, pkt5, offset)
	f.Fuzz(func(t *testing.T, pkt0, pkt1, pkt2, pkt3, pkt4, pkt5 []byte, offset int) {
		pkts := [][]byte{pkt0, pkt1, pkt2, pkt3, pkt4, pkt5}
		toWrite := make([]int, 0, len(pkts))
		handleGRO(pkts, offset, newTCPGROTable(), newTCPGROTable(), &toWrite)
		if len(toWrite) > len(pkts) {
			t.Errorf("len(toWrite): %d > len(pkts): %d", len(toWrite), len(pkts))
		}
		seenWriteI := make(map[int]bool)
		for _, writeI := range toWrite {
			if writeI < 0 || writeI > len(pkts)-1 {
				t.Errorf("toWrite value (%d) outside bounds of len(pkts): %d", writeI, len(pkts))
			}
			if seenWriteI[writeI] {
				t.Errorf("duplicate toWrite value: %d", writeI)
			}
			seenWriteI[writeI] = true
		}
	})
}

func Test_handleGRO(t *testing.T) {
	tests := []struct {
		name        string
		pktsIn      [][]byte
		wantToWrite []int
		wantLens    []int
		wantErr     bool
	}{
		{
			"multiple flows",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201), // v4 flow 2
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),   // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101), // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201), // v6 flow 2
			},
			[]int{0, 2, 3, 5},
			[]int{240, 140, 260, 160},
			false,
		},
		{
			"PSH interleaved",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),                     // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 100, 101), // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),                   // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 301),                   // v4 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),                     // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 100, 101), // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 201),                   // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 301),                   // v6 flow 1
			},
			[]int{0, 2, 4, 6},
			[]int{240, 240, 260, 260},
			false,
		},
		{
			"coalesceItemInvalidCSum",
			[][]byte{
				flipTCP4Checksum(tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)), // v4 flow 1 seq 1 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101),                 // v4 flow 1 seq 101 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),                 // v4 flow 1 seq 201 len 100
			},
			[]int{0, 1},
			[]int{140, 240},
			false,
		},
		{
			"out of order",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // v4 flow 1 seq 101 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // v4 flow 1 seq 1 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201), // v4 flow 1 seq 201 len 100
			},
			[]int{0},
			[]int{340},
			false,
		},
		{
			"tcp4 unequal TTL",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.TTL++
				}),
			},
			[]int{0, 1},
			[]int{140, 140},
			false,
		},
		{
			"tcp4 unequal ToS",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.TOS++
				}),
			},
			[]int{0, 1},
			[]int{140, 140},
			false,
		},
		{
			"tcp4 unequal flags more fragments set",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.Flags = 1
				}),
			},
			[]int{0, 1},
			[]int{140, 140},
			false,
		},
		{
			"tcp4 unequal flags DF set",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.Flags = 2
				}),
			},
			[]int{0, 1},
			[]int{140, 140},
			false,
		},
		{
			"tcp6 unequal hop limit",
			[][]byte{
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),
				tcp6PacketMutateIPFields(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv6Fields) {
					fields.HopLimit++
				}),
			},
			[]int{0, 1},
			[]int{160, 160},
			false,
		},
		{
			"tcp6 unequal traffic class",
			[][]byte{
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),
				tcp6PacketMutateIPFields(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv6Fields) {
					fields.TrafficClass++
				}),
			},
			[]int{0, 1},
			[]int{160, 160},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toWrite := make([]int, 0, len(tt.pktsIn))
			err := handleGRO(tt.pktsIn, offset, newTCPGROTable(), newTCPGROTable(), &toWrite)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("got err: %v", err)
			}
			if len(toWrite) != len(tt.wantToWrite) {
				t.Fatalf("got %d packets, wanted %d", len(toWrite), len(tt.wantToWrite))
			}
			for i, pktI := range tt.wantToWrite {
				if tt.wantToWrite[i] != toWrite[i] {
					t.Fatalf("wantToWrite[%d]: %d != toWrite: %d", i, tt.wantToWrite[i], toWrite[i])
				}
				if tt.wantLens[i] != len(tt.pktsIn[pktI][offset:]) {
					t.Errorf("wanted len %d packet at %d, got: %d", tt.wantLens[i], i, len(tt.pktsIn[pktI][offset:]))
				}
			}
		})
	}
}

func Test_isTCP4NoIPOptions(t *testing.T) {
	valid := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)[virtioNetHdrLen:]
	invalidLen := valid[:39]
	invalidHeaderLen := make([]byte, len(valid))
	copy(invalidHeaderLen, valid)
	invalidHeaderLen[0] = 0x46
	invalidProtocol := make([]byte, len(valid))
	copy(invalidProtocol, valid)
	invalidProtocol[9] = unix.IPPROTO_TCP + 1

	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{
			"valid",
			valid,
			true,
		},
		{
			"invalid length",
			invalidLen,
			false,
		},
		{
			"invalid version",
			[]byte{0x00},
			false,
		},
		{
			"invalid header len",
			invalidHeaderLen,
			false,
		},
		{
			"invalid protocol",
			invalidProtocol,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTCP4NoIPOptions(tt.b); got != tt.want {
				t.Errorf("isTCP4NoIPOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}
