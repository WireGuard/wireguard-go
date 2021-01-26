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
	device.log.Verbosef("Routine: event worker - started")

	for event := range device.tun.device.Events() {
		if event&tun.EventMTUUpdate != 0 {
			mtu, err := device.tun.device.MTU()
			old := atomic.LoadInt32(&device.tun.mtu)
			if err != nil {
				device.log.Errorf("Failed to load updated MTU of device: %v", err)
			} else if int(old) != mtu {
				if mtu+MessageTransportSize > MaxMessageSize {
					device.log.Verbosef("MTU updated: %v (too large)", mtu)
				} else {
					device.log.Verbosef("MTU updated: %v", mtu)
				}
				atomic.StoreInt32(&device.tun.mtu, int32(mtu))
			}
		}

		if event&tun.EventUp != 0 && !setUp {
			device.log.Verbosef("Interface set up")
			setUp = true
			device.Up()
		}

		if event&tun.EventDown != 0 && setUp {
			device.log.Verbosef("Interface set down")
			setUp = false
			device.Down()
		}
	}

	device.log.Verbosef("Routine: event worker - stopped")
	device.state.stopping.Done()
}
