/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun/wintun"
)

const (
	packetAlignment    uint32 = 4        // Number of bytes packets are aligned to in rings
	packetSizeMax      uint32 = 0xffff   // Maximum packet size
	packetCapacity     uint32 = 0x800000 // Ring capacity, 8MiB
	packetTrailingSize uint32 = uint32(unsafe.Sizeof(packetHeader{})) + ((packetSizeMax + (packetAlignment - 1)) &^ (packetAlignment - 1)) - packetAlignment

	ioctlRegisterRings uint32 = (0x22 /*FILE_DEVICE_UNKNOWN*/ << 16) | (0x800 << 2) | 0 /*METHOD_BUFFERED*/ | (0x3 /*FILE_READ_DATA | FILE_WRITE_DATA*/ << 14)

	retryRate    = 4  // Number of retries per second to reopen device pipe
	retryTimeout = 30 // Number of seconds to tolerate adapter unavailable
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

type NativeTun struct {
	wt        *wintun.Wintun
	tunDev    windows.Handle
	tunLock   sync.Mutex
	close     bool
	rings     ringDescriptor
	events    chan Event
	errors    chan error
	forcedMTU int
}

func packetAlign(size uint32) uint32 {
	return (size + (packetAlignment - 1)) &^ (packetAlignment - 1)
}

var shouldRetryOpen = windows.RtlGetVersion().MajorVersion < 10

func maybeRetry(x int) int {
	if shouldRetryOpen {
		return x
	}
	return 0
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
	wt, err = wintun.GetInterface(ifname)
	if err == nil {
		// If so, we delete it, in case it has weird residual configuration.
		_, err = wt.DeleteInterface()
		if err != nil {
			return nil, fmt.Errorf("Unable to delete already existing Wintun interface: %v", err)
		}
	} else if err == windows.ERROR_ALREADY_EXISTS {
		return nil, fmt.Errorf("Foreign network interface with the same name exists")
	}
	wt, _, err = wintun.CreateInterface("WireGuard Tunnel Adapter", requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Wintun interface: %v", err)
	}

	err = wt.SetInterfaceName(ifname)
	if err != nil {
		wt.DeleteInterface()
		return nil, fmt.Errorf("Unable to set name of Wintun interface: %v", err)
	}

	tun := &NativeTun{
		wt:        wt,
		tunDev:    windows.InvalidHandle,
		events:    make(chan Event, 10),
		errors:    make(chan error, 1),
		forcedMTU: 1500,
	}

	tun.rings.send.size = uint32(unsafe.Sizeof(ring{}))
	tun.rings.send.ring = &ring{}
	tun.rings.send.tailMoved, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		wt.DeleteInterface()
		return nil, fmt.Errorf("Error creating event: %v", err)
	}

	tun.rings.receive.size = uint32(unsafe.Sizeof(ring{}))
	tun.rings.receive.ring = &ring{}
	tun.rings.receive.tailMoved, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(tun.rings.send.tailMoved)
		wt.DeleteInterface()
		return nil, fmt.Errorf("Error creating event: %v", err)
	}

	_, err = tun.getTUN()
	if err != nil {
		windows.CloseHandle(tun.rings.send.tailMoved)
		windows.CloseHandle(tun.rings.receive.tailMoved)
		tun.closeTUN()
		wt.DeleteInterface()
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) openTUN() error {
	filename, err := tun.wt.NdisFileName()
	if err != nil {
		return err
	}

	retries := maybeRetry(retryTimeout * retryRate)
	if tun.close {
		return os.ErrClosed
	}

	name, err := windows.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}
	for tun.tunDev == windows.InvalidHandle {
		tun.tunDev, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			if retries > 0 && !tun.close {
				time.Sleep(time.Second / retryRate)
				retries--
				continue
			}
			return err
		}

		atomic.StoreUint32(&tun.rings.send.ring.head, 0)
		atomic.StoreUint32(&tun.rings.send.ring.tail, 0)
		atomic.StoreInt32(&tun.rings.send.ring.alertable, 0)
		atomic.StoreUint32(&tun.rings.receive.ring.head, 0)
		atomic.StoreUint32(&tun.rings.receive.ring.tail, 0)
		atomic.StoreInt32(&tun.rings.receive.ring.alertable, 0)

		var bytesReturned uint32
		err = windows.DeviceIoControl(tun.tunDev, ioctlRegisterRings, (*byte)(unsafe.Pointer(&tun.rings)), uint32(unsafe.Sizeof(tun.rings)), nil, 0, &bytesReturned, nil)
		if err != nil {
			return fmt.Errorf("Error registering rings: %v", err)
		}
	}
	return nil
}

func (tun *NativeTun) closeTUN() (err error) {
	for tun.tunDev != windows.InvalidHandle {
		tun.tunLock.Lock()
		if tun.tunDev == windows.InvalidHandle {
			tun.tunLock.Unlock()
			break
		}
		t := tun.tunDev
		tun.tunDev = windows.InvalidHandle
		err = windows.CloseHandle(t)
		tun.tunLock.Unlock()
		break
	}
	return
}

func (tun *NativeTun) getTUN() (handle windows.Handle, err error) {
	handle = tun.tunDev
	if handle == windows.InvalidHandle {
		tun.tunLock.Lock()
		if tun.tunDev != windows.InvalidHandle {
			handle = tun.tunDev
			tun.tunLock.Unlock()
			return
		}
		err = tun.openTUN()
		if err == nil {
			handle = tun.tunDev
		}
		tun.tunLock.Unlock()
		return
	}
	return
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
	windows.SetEvent(tun.rings.send.tailMoved) // wake the reader if it's sleeping
	var err, err2 error
	err = tun.closeTUN()

	if tun.events != nil {
		close(tun.events)
	}

	err2 = windows.CloseHandle(tun.rings.receive.tailMoved)
	if err == nil {
		err = err2
	}

	err2 = windows.CloseHandle(tun.rings.send.tailMoved)
	if err == nil {
		err = err2
	}

	_, err2 = tun.wt.DeleteInterface()
	if err == nil {
		err = err2
	}

	return err
}

func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMTU, nil
}

// TODO: This is a temporary hack. We really need to be monitoring the interface in real time and adapting to MTU changes.
func (tun *NativeTun) ForceMTU(mtu int) {
	tun.forcedMTU = mtu
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

// Note: Read() and Write() assume the caller comes only from a single thread; there's no locking.

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}

	retries := maybeRetry(1000)
top:
	for !tun.close {
		_, err := tun.getTUN()
		if err != nil {
			return 0, err
		}

		buffHead := atomic.LoadUint32(&tun.rings.send.ring.head)
		if buffHead >= packetCapacity {
			return 0, errors.New("send ring head out of bounds")
		}

		start := time.Now()
		var buffTail uint32
		for {
			buffTail = atomic.LoadUint32(&tun.rings.send.ring.tail)
			if buffHead != buffTail {
				break
			}
			if tun.close {
				return 0, os.ErrClosed
			}
			if time.Since(start) >= time.Millisecond*50 {
				windows.WaitForSingleObject(tun.rings.send.tailMoved, windows.INFINITE)
				continue top
			}
			procyield(1)
		}
		if buffTail >= packetCapacity {
			if retries > 0 {
				tun.closeTUN()
				time.Sleep(time.Millisecond * 2)
				retries--
				continue
			}
			return 0, errors.New("send ring tail out of bounds")
		}
		retries = maybeRetry(1000)

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
		return int(packet.size), nil
	}

	return 0, os.ErrClosed
}

func (tun *NativeTun) Flush() error {
	return nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	retries := maybeRetry(1000)
	for {
		_, err := tun.getTUN()
		if err != nil {
			return 0, err
		}

		packetSize := uint32(len(buff) - offset)
		alignedPacketSize := packetAlign(uint32(unsafe.Sizeof(packetHeader{})) + packetSize)

		buffHead := atomic.LoadUint32(&tun.rings.receive.ring.head)
		if buffHead >= packetCapacity {
			if retries > 0 {
				tun.closeTUN()
				time.Sleep(time.Millisecond * 2)
				retries--
				continue
			}
			return 0, errors.New("receive ring head out of bounds")
		}
		retries = maybeRetry(1000)

		buffTail := atomic.LoadUint32(&tun.rings.receive.ring.tail)
		if buffTail >= packetCapacity {
			return 0, errors.New("receive ring tail out of bounds")
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
}

// LUID returns Windows adapter instance ID.
func (tun *NativeTun) LUID() uint64 {
	return tun.wt.LUID()
}

// wrap returns value modulo ring capacity
func (rb *ring) wrap(value uint32) uint32 {
	return value & (packetCapacity - 1)
}
