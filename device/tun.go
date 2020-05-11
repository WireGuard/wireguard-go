/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	setUp := false

	device.log.Debug("Routine: event worker - started")
	device.state.starting.Done()

	for event := range device.tun.device.Events() {
		if event&tun.EventMTUUpdate != 0 {
			mtu, err := device.tun.device.MTU()
			old := atomic.LoadInt32(&device.tun.mtu)
			if err != nil {
				device.log.Error("Failed to load updated MTU of device:", err)
			} else if int(old) != mtu {
				if mtu+MessageTransportSize > MaxMessageSize {
					device.log.Info("MTU updated:", mtu, "(too large)")
				} else {
					device.log.Info("MTU updated:", mtu)
				}
				atomic.StoreInt32(&device.tun.mtu, int32(mtu))
			}
		}

		if event&tun.EventUp != 0 && !setUp {
			device.log.Info("Interface set up")
			setUp = true
			device.Up()
		}

		if event&tun.EventDown != 0 && setUp {
			device.log.Info("Interface set down")
			setUp = false
			device.Down()
		}
	}

	device.log.Debug("Routine: event worker - stopped")
	device.state.stopping.Done()
}
