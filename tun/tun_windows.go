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
	retryTimeout                   = 30                               // Number of seconds to tolerate adapter unavailable
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
	wt           *wintun.Wintun
	tunFileRead  *os.File
	tunFileWrite *os.File
	tunLock      sync.Mutex
	close        bool
	rdBuff       *exchgBufRead
	wrBuff       *exchgBufWrite
	events       chan TUNEvent
	errors       chan error
	forcedMtu    int
}

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
		return nil, err
	}

	err = wt.FlushInterface()
	if err != nil {
		wt.DeleteInterface(0)
		return nil, errors.New("Flushing interface failed: " + err.Error())
	}

	return &NativeTun{
		wt:        wt,
		rdBuff:    &exchgBufRead{},
		wrBuff:    &exchgBufWrite{},
		events:    make(chan TUNEvent, 10),
		errors:    make(chan error, 1),
		forcedMtu: 1500,
	}, nil
}

func (tun *NativeTun) openTUN() error {
	retries := retryTimeout * retryRate
	if tun.close {
		return os.ErrClosed
	}

	var err error
	name := tun.wt.DataFileName()
	for tun.tunFileRead == nil {
		tun.tunFileRead, err = os.OpenFile(name, os.O_RDONLY, 0)
		if err != nil {
			if retries > 0 && !tun.close {
				time.Sleep(time.Second / retryRate)
				retries--
				continue
			}
			return err
		}
	}
	for tun.tunFileWrite == nil {
		tun.tunFileWrite, err = os.OpenFile(name, os.O_WRONLY, 0)
		if err != nil {
			if retries > 0 && !tun.close {
				time.Sleep(time.Second / retryRate)
				retries--
				continue
			}
			return err
		}
	}
	return nil
}

func (tun *NativeTun) closeTUN() (err error) {
	for tun.tunFileRead != nil {
		tun.tunLock.Lock()
		if tun.tunFileRead == nil {
			tun.tunLock.Unlock()
			break
		}
		t := tun.tunFileRead
		tun.tunFileRead = nil
		windows.CancelIoEx(windows.Handle(t.Fd()), nil)
		err = t.Close()
		tun.tunLock.Unlock()
		break
	}
	for tun.tunFileWrite != nil {
		tun.tunLock.Lock()
		if tun.tunFileWrite == nil {
			tun.tunLock.Unlock()
			break
		}
		t := tun.tunFileWrite
		tun.tunFileWrite = nil
		windows.CancelIoEx(windows.Handle(t.Fd()), nil)
		err2 := t.Close()
		tun.tunLock.Unlock()
		if err == nil {
			err = err2
		}
		break
	}
	return
}

func (tun *NativeTun) getTUN() (read *os.File, write *os.File, err error) {
	read, write = tun.tunFileRead, tun.tunFileWrite
	if read == nil || write == nil {
		read, write = nil, nil
		tun.tunLock.Lock()
		if tun.tunFileRead != nil && tun.tunFileWrite != nil {
			read, write = tun.tunFileRead, tun.tunFileWrite
			tun.tunLock.Unlock()
			return
		}
		err = tun.closeTUN()
		if err != nil {
			tun.tunLock.Unlock()
			return
		}
		err = tun.openTUN()
		if err == nil {
			read, write = tun.tunFileRead, tun.tunFileWrite
		}
		tun.tunLock.Unlock()
		return
	}
	return
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
		file, _, err := tun.getTUN()
		if err != nil {
			return 0, err
		}

		// Fill queue.
		retries := 1000
		for {
			n, err := file.Read(tun.rdBuff.data[:])
			if err != nil {
				tun.rdBuff.offset = 0
				tun.rdBuff.avail = 0
				pe, ok := err.(*os.PathError)
				if tun.close {
					return 0, os.ErrClosed
				}
				if retries > 0 && ok && pe.Err == windows.ERROR_OPERATION_ABORTED {
					retries--
					continue
				}
				if ok && pe.Err == syscall.Errno(6) /*windows.ERROR_INVALID_HANDLE*/ {
					tun.closeTUN()
					break
				}
				return 0, err
			}
			tun.rdBuff.offset = 0
			tun.rdBuff.avail = uint32(n)
			break
		}
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *NativeTun) Flush() error {
	if tun.wrBuff.offset == 0 {
		return nil
	}

	for {
		// Get TUN data pipe.
		_, file, err := tun.getTUN()
		if err != nil {
			return err
		}

		// Flush write buffer.
		retries := retryTimeout * retryRate
		for {
			_, err = file.Write(tun.wrBuff.data[:tun.wrBuff.offset])
			tun.wrBuff.packetNum = 0
			tun.wrBuff.offset = 0
			if err != nil {
				pe, ok := err.(*os.PathError)
				if tun.close {
					return os.ErrClosed
				}
				if retries > 0 && ok && pe.Err == windows.ERROR_OPERATION_ABORTED {
					time.Sleep(time.Second / retryRate)
					retries--
					continue
				}
				if ok && pe.Err == syscall.Errno(6) /*windows.ERROR_INVALID_HANDLE*/ {
					tun.closeTUN()
					break
				}
				return err
			}
			return nil
		}
	}
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
		err := tun.Flush()
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
	return len(buff) - offset, nil
}

//
// GUID returns Windows adapter instance ID.
//
func (tun *NativeTun) GUID() windows.GUID {
	return tun.wt.CfgInstanceID
}
