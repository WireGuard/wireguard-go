/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"git.zx2c4.com/wireguard-go/tun"
	"sync/atomic"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	setUp := false
	logDebug := device.log.Debug
	logInfo := device.log.Info
	logError := device.log.Error

	logDebug.Println("Routine: event worker - started")
	device.state.starting.Done()

	for event := range device.tun.device.Events() {
		if event&tun.TUNEventMTUUpdate != 0 {
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

		if event&tun.TUNEventUp != 0 && !setUp {
			logInfo.Println("Interface set up")
			setUp = true
			device.Up()
		}

		if event&tun.TUNEventDown != 0 && setUp {
			logInfo.Println("Interface set down")
			setUp = false
			device.Down()
		}
	}

	logDebug.Println("Routine: event worker - stopped")
	device.state.stopping.Done()
}
