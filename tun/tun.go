/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"net"
	"os"
	"sync"
)

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

// TCPBasedTUN is a wrapper for a TUN device that communicates over TCP
type TCPBasedTUN struct {
	dev      Device
	tcpConn  net.Conn
	mutex    sync.Mutex
	isClosed bool
}

// NewTCPTUN creates a new TCP-based TUN device
func NewTCPTUN(base Device, conn net.Conn) *TCPBasedTUN {
	return &TCPBasedTUN{
		dev:     base,
		tcpConn: conn,
	}
}

// ReadTCP reads a packet from the TCP connection
func (tun *TCPBasedTUN) ReadTCP(packet []byte) (int, error) {
	tun.mutex.Lock()
	defer tun.mutex.Unlock()
	
	if tun.isClosed || tun.tcpConn == nil {
		return 0, os.ErrClosed
	}
	
	return tun.tcpConn.Read(packet)
}

// WriteTCP writes a packet to the TCP connection
func (tun *TCPBasedTUN) WriteTCP(packet []byte) (int, error) {
	tun.mutex.Lock()
	defer tun.mutex.Unlock()
	
	if tun.isClosed || tun.tcpConn == nil {
		return 0, os.ErrClosed
	}
	
	return tun.tcpConn.Write(packet)
}

// SetTCPConn sets a new TCP connection for the TUN
func (tun *TCPBasedTUN) SetTCPConn(conn net.Conn) {
	tun.mutex.Lock()
	defer tun.mutex.Unlock()
	
	if tun.tcpConn != nil {
		tun.tcpConn.Close()
	}
	
	tun.tcpConn = conn
	tun.isClosed = false
}

// CloseTCP closes the TCP connection
func (tun *TCPBasedTUN) CloseTCP() error {
	tun.mutex.Lock()
	defer tun.mutex.Unlock()
	
	if tun.isClosed || tun.tcpConn == nil {
		return nil
	}
	
	tun.isClosed = true
	return tun.tcpConn.Close()
}

type Device interface {
	// File returns the file descriptor of the device.
	File() *os.File

	// Read one or more packets from the Device (without any additional headers).
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// A nonzero offset can be used to instruct the Device on where to begin
	// reading into each element of the bufs slice.
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)

	// Write one or more packets to the device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, offset int) (int, error)

	// MTU returns the MTU of the Device.
	MTU() (int, error)

	// Name returns the current name of the Device.
	Name() (string, error)

	// Events returns a channel of type Event, which is fed Device events.
	Events() <-chan Event

	// Close stops the Device and closes the Event channel.
	Close() error

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int
}
