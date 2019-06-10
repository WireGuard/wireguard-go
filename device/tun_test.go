/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// newDummyTUN creates a dummy TUN device with the specified name.
func newDummyTUN(name string) tun.Device {
	return &dummyTUN{
		name:    name,
		packets: make(chan []byte, 100),
		events:  make(chan tun.Event, 10),
	}
}

// A dummyTUN is a tun.Device which is used in unit tests.
type dummyTUN struct {
	name    string
	mtu     int
	packets chan []byte
	events  chan tun.Event
}

func (d *dummyTUN) Events() chan tun.Event { return d.events }
func (*dummyTUN) File() *os.File           { return nil }
func (*dummyTUN) Flush() error             { return nil }
func (d *dummyTUN) MTU() (int, error)      { return d.mtu, nil }
func (d *dummyTUN) Name() (string, error)  { return d.name, nil }

func (d *dummyTUN) Close() error {
	close(d.events)
	close(d.packets)
	return nil
}

func (d *dummyTUN) Read(b []byte, offset int) (int, error) {
	buf, ok := <-d.packets
	if !ok {
		return 0, errors.New("device closed")
	}
	copy(b[offset:], buf)
	return len(buf), nil
}

func (d *dummyTUN) Write(b []byte, offset int) (int, error) {
	d.packets <- b[offset:]
	return len(b), nil
}
