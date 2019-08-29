/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun/wintun"
)

const (
	packetAlignment            = 4        // Number of bytes packets are aligned to in rings
	packetSizeMax              = 0xffff   // Maximum packet size
	packetCapacity             = 0x800000 // Ring capacity, 8MiB
	packetTrailingSize         = uint32(unsafe.Sizeof(packetHeader{})) + ((packetSizeMax + (packetAlignment - 1)) &^ (packetAlignment - 1)) - packetAlignment
	ioctlRegisterRings         = (51820 << 16) | (0x970 << 2) | 0 /*METHOD_BUFFERED*/ | (0x3 /*FILE_READ_DATA | FILE_WRITE_DATA*/ << 14)
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)

type packetHeader struct {
	size uint32
}

type packet struct {
	packetHeader
	data [packetSizeMax]byte
}

type ring struct {
	head      uint32
	tail      uint32
	alertable int32
	data      [packetCapacity + packetTrailingSize]byte
}

type ringDescriptor struct {
	send, receive struct {
		size      uint32
		ring      *ring
		tailMoved windows.Handle
	}
}

type rateJuggler struct {
	current       uint64
	nextByteCount uint64
	nextStartTime int64
	changing      int32
}

type NativeTun struct {
	wt        *wintun.Wintun
	handle    windows.Handle
	close     bool
	rings     ringDescriptor
	events    chan Event
	errors    chan error
	forcedMTU int
	rate      rateJuggler
}

const WintunPool = wintun.Pool("WireGuard")

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

func packetAlign(size uint32) uint32 {
	return (size + (packetAlignment - 1)) &^ (packetAlignment - 1)
}

//
// CreateTUN creates a Wintun adapter with the given name. Should a Wintun
// adapter with the same name exist, it is reused.
//
func CreateTUN(ifname string) (Device, error) {
	return CreateTUNWithRequestedGUID(ifname, nil)
}

//
// CreateTUNWithRequestedGUID creates a Wintun adapter with the given name and
// a requested GUID. Should a Wintun adapter with the same name exist, it is reused.
//
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID) (Device, error) {
	var err error
	var wt *wintun.Wintun

	// Does an interface with this name already exist?
	wt, err = WintunPool.GetInterface(ifname)
	if err == nil {
		// If so, we delete it, in case it has weird residual configuration.
		_, err = wt.DeleteInterface()
		if err != nil {
			return nil, fmt.Errorf("Unable to delete already existing Wintun interface: %v", err)
		}
	}
	wt, _, err = WintunPool.CreateInterface(requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Wintun interface: %v", err)
	}

	err = wt.SetInterfaceName(ifname, WintunPool)
	if err != nil {
		wt.DeleteInterface()
		return nil, fmt.Errorf("Unable to set name of Wintun interface: %v", err)
	}

	tun := &NativeTun{
		wt:        wt,
		handle:    windows.InvalidHandle,
		events:    make(chan Event, 10),
		errors:    make(chan error, 1),
		forcedMTU: 1500,
	}

	tun.rings.send.size = uint32(unsafe.Sizeof(ring{}))
	tun.rings.send.ring = &ring{}
	tun.rings.send.tailMoved, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("Error creating event: %v", err)
	}

	tun.rings.receive.size = uint32(unsafe.Sizeof(ring{}))
	tun.rings.receive.ring = &ring{}
	tun.rings.receive.tailMoved, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("Error creating event: %v", err)
	}

	tun.handle, err = tun.wt.AdapterHandle()
	if err != nil {
		tun.Close()
		return nil, err
	}

	var bytesReturned uint32
	err = windows.DeviceIoControl(tun.handle, ioctlRegisterRings, (*byte)(unsafe.Pointer(&tun.rings)), uint32(unsafe.Sizeof(tun.rings)), nil, 0, &bytesReturned, nil)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("Error registering rings: %v", err)
	}
	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.wt.InterfaceName()
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	tun.close = true
	if tun.rings.send.tailMoved != 0 {
		windows.SetEvent(tun.rings.send.tailMoved) // wake the reader if it's sleeping
	}
	if tun.handle != windows.InvalidHandle {
		windows.CloseHandle(tun.handle)
	}
	if tun.rings.send.tailMoved != 0 {
		windows.CloseHandle(tun.rings.send.tailMoved)
	}
	if tun.rings.send.tailMoved != 0 {
		windows.CloseHandle(tun.rings.receive.tailMoved)
	}
	var err error
	if tun.wt != nil {
		_, err = tun.wt.DeleteInterface()
	}
	close(tun.events)
	return err
}

func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMTU, nil
}

// TODO: This is a temporary hack. We really need to be monitoring the interface in real time and adapting to MTU changes.
func (tun *NativeTun) ForceMTU(mtu int) {
	tun.forcedMTU = mtu
}

// Note: Read() and Write() assume the caller comes only from a single thread; there's no locking.

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
retry:
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}
	if tun.close {
		return 0, os.ErrClosed
	}

	buffHead := atomic.LoadUint32(&tun.rings.send.ring.head)
	if buffHead >= packetCapacity {
		return 0, os.ErrClosed
	}

	start := nanotime()
	shouldSpin := atomic.LoadUint64(&tun.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&tun.rate.nextStartTime)) <= rateMeasurementGranularity*2
	var buffTail uint32
	for {
		buffTail = atomic.LoadUint32(&tun.rings.send.ring.tail)
		if buffHead != buffTail {
			break
		}
		if tun.close {
			return 0, os.ErrClosed
		}
		if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
			windows.WaitForSingleObject(tun.rings.send.tailMoved, windows.INFINITE)
			goto retry
		}
		procyield(1)
	}
	if buffTail >= packetCapacity {
		return 0, os.ErrClosed
	}

	buffContent := tun.rings.send.ring.wrap(buffTail - buffHead)
	if buffContent < uint32(unsafe.Sizeof(packetHeader{})) {
		return 0, errors.New("incomplete packet header in send ring")
	}

	packet := (*packet)(unsafe.Pointer(&tun.rings.send.ring.data[buffHead]))
	if packet.size > packetSizeMax {
		return 0, errors.New("packet too big in send ring")
	}

	alignedPacketSize := packetAlign(uint32(unsafe.Sizeof(packetHeader{})) + packet.size)
	if alignedPacketSize > buffContent {
		return 0, errors.New("incomplete packet in send ring")
	}

	copy(buff[offset:], packet.data[:packet.size])
	buffHead = tun.rings.send.ring.wrap(buffHead + alignedPacketSize)
	atomic.StoreUint32(&tun.rings.send.ring.head, buffHead)
	tun.rate.update(uint64(packet.size))
	return int(packet.size), nil
}

func (tun *NativeTun) Flush() error {
	return nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	if tun.close {
		return 0, os.ErrClosed
	}

	packetSize := uint32(len(buff) - offset)
	tun.rate.update(uint64(packetSize))
	alignedPacketSize := packetAlign(uint32(unsafe.Sizeof(packetHeader{})) + packetSize)

	buffHead := atomic.LoadUint32(&tun.rings.receive.ring.head)
	if buffHead >= packetCapacity {
		return 0, os.ErrClosed
	}

	buffTail := atomic.LoadUint32(&tun.rings.receive.ring.tail)
	if buffTail >= packetCapacity {
		return 0, os.ErrClosed
	}

	buffSpace := tun.rings.receive.ring.wrap(buffHead - buffTail - packetAlignment)
	if alignedPacketSize > buffSpace {
		return 0, nil // Dropping when ring is full.
	}

	packet := (*packet)(unsafe.Pointer(&tun.rings.receive.ring.data[buffTail]))
	packet.size = packetSize
	copy(packet.data[:packetSize], buff[offset:])
	atomic.StoreUint32(&tun.rings.receive.ring.tail, tun.rings.receive.ring.wrap(buffTail+alignedPacketSize))
	if atomic.LoadInt32(&tun.rings.receive.ring.alertable) != 0 {
		windows.SetEvent(tun.rings.receive.tailMoved)
	}
	return int(packetSize), nil
}

// LUID returns Windows adapter instance ID.
func (tun *NativeTun) LUID() uint64 {
	return tun.wt.LUID()
}

// wrap returns value modulo ring capacity
func (rb *ring) wrap(value uint32) uint32 {
	return value & (packetCapacity - 1)
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := atomic.AddUint64(&rate.nextByteCount, packetLen)
	period := uint64(now - atomic.LoadInt64(&rate.nextStartTime))
	if period >= rateMeasurementGranularity {
		if !atomic.CompareAndSwapInt32(&rate.changing, 0, 1) {
			return
		}
		atomic.StoreInt64(&rate.nextStartTime, now)
		atomic.StoreUint64(&rate.current, total*uint64(time.Second/time.Nanosecond)/period)
		atomic.StoreUint64(&rate.nextByteCount, 0)
		atomic.StoreInt32(&rate.changing, 0)
	}
}
