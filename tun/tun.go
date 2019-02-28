/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"os"
)

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

func (tun *NativeTun) operateOnFd(fn func(fd uintptr)) {
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		tun.errors <- fmt.Errorf("unable to find sysconn for tunfile: %s", err.Error())
		return
	}
	err = sysconn.Control(fn)
	if err != nil {
		tun.errors <- fmt.Errorf("unable to control sysconn for tunfile: %s", err.Error())
	}
}
