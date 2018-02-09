package main

import (
	"git.zx2c4.com/wireguard-go/internal/events"
	"os"
	"sync/atomic"
)

const DefaultMTU = 1420

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
	Name() string                   // returns the current name
	Events() chan events.Event      // returns a constant channel of events related to the device
	Close() error                   // stops the device and closes the event channel
}

func (device *Device) RoutineTUNEventReader() {
	logInfo := device.log.Info
	logError := device.log.Error

	for event := range device.tun.device.Events() {

		if event.Contains(TUNEventMTUUpdate) {
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

		if event.Contains(TUNEventUp) && !device.isUp.Get() {
			logInfo.Println("Interface set up")
			device.Up()
		}

		if event.Contains(TUNEventDown) && device.isUp.Get() {
			logInfo.Println("Interface set down")
			device.Down()
		}

		event.Processed()
	}
}
