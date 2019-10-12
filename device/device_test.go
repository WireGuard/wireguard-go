/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func TestTwoDevicePing(t *testing.T) {
	// TODO(crawshaw): pick unused ports on localhost
	cfg1 := `private_key=481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58
listen_port=53511
replace_peers=true
public_key=f70dbb6b1b92a1dde1c783b297016af3f572fef13b0abb16a2623d89a58e9725
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.2/32
endpoint=127.0.0.1:53512`
	tun1 := NewChannelTUN()
	dev1 := NewDevice(tun1.TUN(), NewLogger(LogLevelDebug, "dev1: "))
	dev1.Up()
	defer dev1.Close()
	if err := dev1.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg1))); err != nil {
		t.Fatal(err)
	}

	cfg2 := `private_key=98c7989b1661a0d64fd6af3502000f87716b7c4bbcf00d04fc6073aa7b539768
listen_port=53512
replace_peers=true
public_key=49e80929259cebdda4f322d6d2b1a6fad819d603acd26fd5d845e7a123036427
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.1/32
endpoint=127.0.0.1:53511`
	tun2 := NewChannelTUN()
	dev2 := NewDevice(tun2.TUN(), NewLogger(LogLevelDebug, "dev2: "))
	dev2.Up()
	defer dev2.Close()
	if err := dev2.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg2))); err != nil {
		t.Fatal(err)
	}

	t.Run("ping 1.0.0.1", func(t *testing.T) {
		msg2to1 := ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
		tun2.Outbound <- msg2to1
		select {
		case msgRecv := <-tun1.Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-time.After(300 * time.Millisecond):
			t.Error("ping did not transit")
		}
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		msg1to2 := ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		tun1.Outbound <- msg1to2
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(300 * time.Millisecond):
			t.Error("return ping did not transit")
		}
	})
}

func ping(dst, src net.IP) []byte {
	localPort := uint16(1337)
	seq := uint16(0)

	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:], localPort)
	binary.BigEndian.PutUint16(payload[2:], seq)

	return genICMPv4(payload, dst, src)
}

// checksum is the "internet checksum" from https://tools.ietf.org/html/rfc1071.
func checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial)
	for i := 0; i < len(buf)-1; i += 2 {
		v += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	if len(buf)%2 == 1 {
		v += uint32(buf[len(buf)-1]) << 8
	}
	for v > 0xffff {
		v = (v >> 16) + (v & 0xffff)
	}
	return ^uint16(v)
}

func genICMPv4(payload []byte, dst, src net.IP) []byte {
	const (
		icmpv4ProtocolNumber = 1
		icmpv4Echo           = 8
		icmpv4ChecksumOffset = 2
		icmpv4Size           = 8
		ipv4Size             = 20
		ipv4TotalLenOffset   = 2
		ipv4ChecksumOffset   = 10
		ttl                  = 65
	)

	hdr := make([]byte, ipv4Size+icmpv4Size)

	ip := hdr[0:ipv4Size]
	icmpv4 := hdr[ipv4Size : ipv4Size+icmpv4Size]

	// https://tools.ietf.org/html/rfc792
	icmpv4[0] = icmpv4Echo // type
	icmpv4[1] = 0          // code
	chksum := ^checksum(icmpv4, checksum(payload, 0))
	binary.BigEndian.PutUint16(icmpv4[icmpv4ChecksumOffset:], chksum)

	// https://tools.ietf.org/html/rfc760 section 3.1
	length := uint16(len(hdr) + len(payload))
	ip[0] = (4 << 4) | (ipv4Size / 4)
	binary.BigEndian.PutUint16(ip[ipv4TotalLenOffset:], length)
	ip[8] = ttl
	ip[9] = icmpv4ProtocolNumber
	copy(ip[12:], src.To4())
	copy(ip[16:], dst.To4())
	chksum = ^checksum(ip[:], 0)
	binary.BigEndian.PutUint16(ip[ipv4ChecksumOffset:], chksum)

	var v []byte
	v = append(v, hdr...)
	v = append(v, payload...)
	return []byte(v)
}

// TODO(crawshaw): find a reusable home for this. package devicetest?
type ChannelTUN struct {
	Inbound  chan []byte // incoming packets, closed on TUN close
	Outbound chan []byte // outbound packets, blocks forever on TUN close

	closed chan struct{}
	events chan tun.Event
	tun    chTun
}

func NewChannelTUN() *ChannelTUN {
	c := &ChannelTUN{
		Inbound:  make(chan []byte),
		Outbound: make(chan []byte),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 1),
	}
	c.tun.c = c
	c.events <- tun.EventUp
	return c
}

func (c *ChannelTUN) TUN() tun.Device {
	return &c.tun
}

type chTun struct {
	c *ChannelTUN
}

func (t *chTun) File() *os.File { return nil }

func (t *chTun) Read(data []byte, offset int) (int, error) {
	select {
	case <-t.c.closed:
		return 0, io.EOF // TODO(crawshaw): what is the correct error value?
	case msg := <-t.c.Outbound:
		return copy(data[offset:], msg), nil
	}
}

// Write is called by the wireguard device to deliver a packet for routing.
func (t *chTun) Write(data []byte, offset int) (int, error) {
	if offset == -1 {
		close(t.c.closed)
		close(t.c.events)
		return 0, io.EOF
	}
	msg := make([]byte, len(data)-offset)
	copy(msg, data[offset:])
	select {
	case <-t.c.closed:
		return 0, io.EOF // TODO(crawshaw): what is the correct error value?
	case t.c.Inbound <- msg:
		return len(data) - offset, nil
	}
}

func (t *chTun) Flush() error           { return nil }
func (t *chTun) MTU() (int, error)      { return DefaultMTU, nil }
func (t *chTun) Name() (string, error)  { return "loopbackTun1", nil }
func (t *chTun) Events() chan tun.Event { return t.c.events }
func (t *chTun) Close() error {
	t.Write(nil, -1)
	return nil
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := newDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, logger)
	device.SetPrivateKey(sk)
	return device
}
