/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun"
)

const (
	packetExchangeMax       uint32 = 256                              // Number of packets that may be written at a time
	packetExchangeAlignment uint32 = 16                               // Number of bytes packets are aligned to in exchange buffers
	packetSizeMax           uint32 = 0xf000 - packetExchangeAlignment // Maximum packet size
	packetExchangeSize      uint32 = 0x100000                         // Exchange buffer size (defaults to 1MiB)
	retryRate                      = 4                                // Number of retries per second to reopen device pipe
	retryTimeout                   = 5                                // Number of seconds to tolerate adapter unavailable
)

type exchgBufRead struct {
	data   [packetExchangeSize]byte
	offset uint32
	avail  uint32
}

type exchgBufWrite struct {
	data      [packetExchangeSize]byte
	offset    uint32
	packetNum uint32
}

type NativeTun struct {
	wt        *wintun.Wintun
	tunName   *uint16
	tunFile   windows.Handle
	tunLock   sync.Mutex
	close     bool
	rdBuff    *exchgBufRead
	wrBuff    *exchgBufWrite
	rdEvent   windows.Handle
	wrEvent   windows.Handle
	events    chan TUNEvent
	errors    chan error
	forcedMtu int
}

//sys	getOverlappedResult(handle windows.Handle, overlapped *windows.Overlapped, done *uint32, wait bool) (err error) = kernel32.GetOverlappedResult

func packetAlign(size uint32) uint32 {
	return (size + (packetExchangeAlignment - 1)) &^ (packetExchangeAlignment - 1)
}

//
// CreateTUN creates a Wintun adapter with the given name. Should a Wintun
// adapter with the same name exist, it is reused.
//
func CreateTUN(ifname string) (TUNDevice, error) {
	// Does an interface with this name already exist?
	wt, err := wintun.GetInterface(ifname, 0)
	if wt == nil {
		// Interface does not exist or an error occured. Create one.
		wt, _, err = wintun.CreateInterface("WireGuard Tunnel Adapter", 0)
		if err != nil {
			return nil, errors.New("Creating Wintun adapter failed: " + err.Error())
		}
	} else if err != nil {
		// Foreign interface with the same name found.
		// We could create a Wintun interface under a temporary name. But, should our
		// proces die without deleting this interface first, the interface would remain
		// orphaned.
		return nil, err
	}

	err = wt.SetInterfaceName(ifname)
	if err != nil {
		wt.DeleteInterface(0)
		return nil, errors.New("Setting interface name failed: " + err.Error())
	}

	err = wt.FlushInterface()
	if err != nil {
		wt.DeleteInterface(0)
		return nil, errors.New("Flushing interface failed: " + err.Error())
	}

	tunNameUTF16, err := windows.UTF16PtrFromString(wt.DataFileName())
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	rde, err := windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}
	wre, err := windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
	if err != nil {
		windows.CloseHandle(rde)
		wt.DeleteInterface(0)
		return nil, err
	}

	return &NativeTun{
		wt:        wt,
		tunName:   tunNameUTF16,
		tunFile:   windows.InvalidHandle,
		rdBuff:    &exchgBufRead{},
		wrBuff:    &exchgBufWrite{},
		rdEvent:   rde,
		wrEvent:   wre,
		events:    make(chan TUNEvent, 10),
		errors:    make(chan error, 1),
		forcedMtu: 1500,
	}, nil
}

func (tun *NativeTun) openTUN() error {
	retries := retryTimeout * retryRate
	for {
		if tun.close {
			return errors.New("Cancelled")
		}

		file, err := windows.CreateFile(tun.tunName, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_NO_BUFFERING, 0)
		if err != nil {
			if retries > 0 {
				time.Sleep(time.Second / retryRate)
				retries--
				continue
			}
			return err
		}

		tun.tunFile = file
		return nil
	}
}

func (tun *NativeTun) closeTUN() (err error) {
	if tun.tunFile != windows.InvalidHandle {
		tun.tunLock.Lock()
		defer tun.tunLock.Unlock()
		if tun.tunFile == windows.InvalidHandle {
			return
		}
		t := tun.tunFile
		tun.tunFile = windows.InvalidHandle
		err = windows.CloseHandle(t)
	}
	return
}

func (tun *NativeTun) getTUN() (windows.Handle, error) {
	if tun.tunFile == windows.InvalidHandle {
		tun.tunLock.Lock()
		defer tun.tunLock.Unlock()
		if tun.tunFile != windows.InvalidHandle {
			return tun.tunFile, nil
		}
		err := tun.openTUN()
		if err != nil {
			return windows.InvalidHandle, err
		}
	}
	return tun.tunFile, nil
}

func (tun *NativeTun) isIOCancelled(err error) bool {
	// Read&WriteFile() return the same ERROR_OPERATION_ABORTED if we close the handle
	// or the TUN device is put down. We need a "close" flag to distinguish.
	en, ok := err.(syscall.Errno)
	if tun.close && ok && en == windows.ERROR_OPERATION_ABORTED {
		return true
	}
	return false
}

func (tun *NativeTun) Name() (string, error) {
	return tun.wt.GetInterfaceName()
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *NativeTun) Close() error {
	tun.close = true
	err1 := tun.closeTUN()

	if tun.events != nil {
		close(tun.events)
	}

	_, _, err2 := tun.wt.DeleteInterface(0)
	if err1 == nil {
		err1 = err2
	}

	windows.CloseHandle(tun.rdEvent)
	windows.CloseHandle(tun.wrEvent)

	return err1
}

func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMtu, nil
}

//TODO: This is a temporary hack. We really need to be monitoring the interface in real time and adapting to MTU changes.
func (tun *NativeTun) ForceMtu(mtu int) {
	tun.forcedMtu = mtu
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}

	for {
		if tun.rdBuff.offset+packetExchangeAlignment <= tun.rdBuff.avail {
			// Get packet from the exchange buffer.
			packet := tun.rdBuff.data[tun.rdBuff.offset:]
			size := *(*uint32)(unsafe.Pointer(&packet[0]))
			pSize := packetAlign(packetExchangeAlignment + size)
			if packetSizeMax < size || tun.rdBuff.avail < tun.rdBuff.offset+pSize {
				// Invalid packet size.
				tun.rdBuff.avail = 0
				continue
			}
			packet = packet[packetExchangeAlignment : packetExchangeAlignment+size]

			// Copy data.
			copy(buff[offset:], packet)
			tun.rdBuff.offset += pSize
			return int(size), nil
		}

		// Get TUN data pipe.
		file, err := tun.getTUN()
		if err != nil {
			return 0, err
		}

		// Fill queue.
		var n uint32
		overlapped := &windows.Overlapped{HEvent: tun.rdEvent}
		err = windows.ReadFile(file, tun.rdBuff.data[:], &n, overlapped)
		if err != nil {
			if en, ok := err.(syscall.Errno); ok && en == windows.ERROR_IO_PENDING {
				err = getOverlappedResult(file, overlapped, &n, true)
			}
			if err != nil {
				tun.rdBuff.avail = 0
				if tun.isIOCancelled(err) {
					return 0, err
				}
				tun.closeTUN()
				continue
			}
		}
		tun.rdBuff.offset = 0
		tun.rdBuff.avail = uint32(n)
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *NativeTun) flush() error {
	// Get TUN data pipe.
	file, err := tun.getTUN()
	if err != nil {
		return err
	}

	// Flush write buffer.
	var n uint32
	overlapped := &windows.Overlapped{HEvent: tun.wrEvent}
	err = windows.WriteFile(file, tun.wrBuff.data[:tun.wrBuff.offset], &n, overlapped)
	tun.wrBuff.packetNum = 0
	tun.wrBuff.offset = 0
	if err != nil {
		if en, ok := err.(syscall.Errno); ok && en == windows.ERROR_IO_PENDING {
			err = getOverlappedResult(file, overlapped, &n, true)
		}
		if err != nil {
			if tun.isIOCancelled(err) {
				return err
			}
			tun.closeTUN()
			return nil
		}
	}

	return nil
}

func (tun *NativeTun) putTunPacket(buff []byte) error {
	size := uint32(len(buff))
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > packetSizeMax {
		return errors.New("Packet too big")
	}
	pSize := packetAlign(packetExchangeAlignment + size)

	if tun.wrBuff.packetNum >= packetExchangeMax || tun.wrBuff.offset+pSize >= packetExchangeSize {
		// Exchange buffer is full -> flush first.
		err := tun.flush()
		if err != nil {
			return err
		}
	}

	// Write packet to the exchange buffer.
	packet := tun.wrBuff.data[tun.wrBuff.offset : tun.wrBuff.offset+pSize]
	*(*uint32)(unsafe.Pointer(&packet[0])) = size
	packet = packet[packetExchangeAlignment : packetExchangeAlignment+size]
	copy(packet, buff)

	tun.wrBuff.packetNum++
	tun.wrBuff.offset += pSize

	return nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	err := tun.putTunPacket(buff[offset:])
	if err != nil {
		return 0, err
	}

	// Flush write buffer.
	return len(buff) - offset, tun.flush()
}

//
// GUID returns Windows adapter instance ID.
//
func (tun *NativeTun) GUID() windows.GUID {
	return *(*windows.GUID)(tun.wt)
}
