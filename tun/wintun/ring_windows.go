/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PacketAlignment    = 4        // Number of bytes packets are aligned to in rings
	PacketSizeMax      = 0xffff   // Maximum packet size
	PacketCapacity     = 0x800000 // Ring capacity, 8MiB
	PacketTrailingSize = uint32(unsafe.Sizeof(PacketHeader{})) + ((PacketSizeMax + (PacketAlignment - 1)) &^ (PacketAlignment - 1)) - PacketAlignment
	ioctlRegisterRings = (51820 << 16) | (0x970 << 2) | 0 /*METHOD_BUFFERED*/ | (0x3 /*FILE_READ_DATA | FILE_WRITE_DATA*/ << 14)
)

type PacketHeader struct {
	Size uint32
}

type Packet struct {
	PacketHeader
	Data [PacketSizeMax]byte
}

type Ring struct {
	Head      uint32
	Tail      uint32
	Alertable int32
	Data      [PacketCapacity + PacketTrailingSize]byte
}

type RingDescriptor struct {
	Send, Receive struct {
		Size      uint32
		Ring      *Ring
		TailMoved windows.Handle
	}
}

// Wrap returns value modulo ring capacity
func (rb *Ring) Wrap(value uint32) uint32 {
	return value & (PacketCapacity - 1)
}

// Aligns a packet size to PacketAlignment
func PacketAlign(size uint32) uint32 {
	return (size + (PacketAlignment - 1)) &^ (PacketAlignment - 1)
}

func (descriptor *RingDescriptor) Init() (err error) {
	descriptor.Send.Size = uint32(unsafe.Sizeof(Ring{}))
	descriptor.Send.Ring = &Ring{}
	descriptor.Send.TailMoved, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return
	}

	descriptor.Receive.Size = uint32(unsafe.Sizeof(Ring{}))
	descriptor.Receive.Ring = &Ring{}
	descriptor.Receive.TailMoved, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(descriptor.Send.TailMoved)
		return
	}

	return
}

func (descriptor *RingDescriptor) Close() {
	if descriptor.Send.TailMoved != 0 {
		windows.CloseHandle(descriptor.Send.TailMoved)
		descriptor.Send.TailMoved = 0
	}
	if descriptor.Send.TailMoved != 0 {
		windows.CloseHandle(descriptor.Receive.TailMoved)
		descriptor.Receive.TailMoved = 0
	}
}

func (wintun *Interface) Register(descriptor *RingDescriptor) (windows.Handle, error) {
	handle, err := wintun.handle()
	if err != nil {
		return 0, err
	}
	var bytesReturned uint32
	err = windows.DeviceIoControl(handle, ioctlRegisterRings, (*byte)(unsafe.Pointer(descriptor)), uint32(unsafe.Sizeof(*descriptor)), nil, 0, &bytesReturned, nil)
	if err != nil {
		return 0, err
	}
	return handle, nil
}
