/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

package main

import (
	"os"
	"sync/atomic"
)

const DefaultMTU = 1420

type TUNEvent int

const (
	TUNEventUp = 1 << iota
	TUNEventDown
	TUNEventMTUUpdate
)

type TUNDevice interface {
	File() *os.File                 // returns the file descriptor of the device
	Read([]byte, int) (int, error)  // read a packet from the device (without any additional headers)
	Write([]byte, int) (int, error) // writes a packet to the device (without any additional headers)
	MTU() (int, error)              // returns the MTU of the device
	Name() (string, error)          // fetches and returns the current name
	Events() chan TUNEvent          // returns a constant channel of events related to the device
	Close() error                   // stops the device and closes the event channel
}

func (device *Device) RoutineTUNEventReader() {
	setUp := false
	logInfo := device.log.Info
	logError := device.log.Error

	device.state.starting.Done()

	for event := range device.tun.device.Events() {
		if event&TUNEventMTUUpdate != 0 {
			mtu, err := device.tun.device.MTU()
			old := atomic.LoadInt32(&device.tun.mtu)
			if err != nil {
				logError.Println("Failed to load updated MTU of device:", err)
			} else if int(old) != mtu {
				if mtu+MessageTransportSize > MaxMessageSize {
					logInfo.Println("MTU updated:", mtu, "(too large)")
				} else {
					logInfo.Println("MTU updated:", mtu)
				}
				atomic.StoreInt32(&device.tun.mtu, int32(mtu))
			}
		}

		if event&TUNEventUp != 0 && !setUp {
			logInfo.Println("Interface set up")
			setUp = true
			device.Up()
		}

		if event&TUNEventDown != 0 && setUp {
			logInfo.Println("Interface set down")
			setUp = false
			device.Down()
		}
	}

	device.state.stopping.Done()
}
