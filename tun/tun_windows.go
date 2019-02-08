/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"git.zx2c4.com/wireguard-go/tun/wintun"
	"golang.org/x/sys/windows"
)

const (
	packetSizeMax      = 1600
	packetExchangeMax  = 256 // Number of packets that can be exchanged at a time
)

const (
	signalClose = iota
	signalDataAvail

	signalMax
)

type tunPacket struct {
	size uint32
	data [packetSizeMax]byte
}

type tunRWQueue struct {
	numPackets uint32
	packets    [packetExchangeMax]tunPacket
	left       bool
}

type nativeTun struct {
	wt           *wintun.Wintun
	tunName      string
	signalName   *uint16
	tunFile      *os.File
	wrBuff       tunRWQueue
	rdBuff       tunRWQueue
	signals      [signalMax]windows.Handle
	rdNextPacket uint32
	events       chan TUNEvent
	errors       chan error
}

func CreateTUN(ifname string) (TUNDevice, error) {
	// Does an interface with this name already exist?
	wt, err := wintun.GetInterface(ifname, 0)
	if wt == nil {
		// Interface does not exist or an error occured. Create one.
		wt, _, err = wintun.CreateInterface("WireGuard Tunnel Adapter", 0)
		if err != nil {
			return nil, err
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
		return nil, err
	}

	signalNameUTF16, err := windows.UTF16PtrFromString(wt.SignalEventName())
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	// Create instance.
	tun := &nativeTun{
		wt:         wt,
		tunName:    wt.DataFileName(),
		signalName: signalNameUTF16,
		events:     make(chan TUNEvent, 10),
		errors:     make(chan error, 1),
	}

	// Create close event.
	tun.signals[signalClose], err = windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	return tun, nil
}

func (tun *nativeTun) openTUN() error {
	for {
		// Open interface data pipe.
		// Data pipe must be opened first, as the interface data available event is created when somebody actually connects to the data pipe.
		file, err := os.OpenFile(tun.tunName, os.O_RDWR|os.O_SYNC, 0600)
		if err != nil {
			// After examining possible error conditions, many arose that were only temporary: windows.ERROR_FILE_NOT_FOUND, "read <filename> closed", etc.
			// To simplify, we will enter a retry-loop on _any_ error until session is closed by user.
			switch evt, e := windows.WaitForSingleObject(tun.signals[signalClose], 1000); evt {
			case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
				return errors.New("TUN closed")
			case windows.WAIT_TIMEOUT:
				continue
			default:
				return errors.New("Unexpected result from WaitForSingleObject: " + e.Error())
			}
		}

		// Open interface data available event.
		event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, tun.signalName)
		if err != nil {
			file.Close()
			return errors.New("Opening interface data ready event failed: " + err.Error())
		}

		tun.tunFile = file
		tun.signals[signalDataAvail] = event

		return nil
	}
}

func (tun *nativeTun) closeTUN() (err error) {
	if tun.signals[signalDataAvail] != 0 {
		// Close interface data ready event.
		e := windows.CloseHandle(tun.signals[signalDataAvail])
		if err != nil {
			err = e
		}

		tun.signals[signalDataAvail] = 0
	}

	if tun.tunFile != nil {
		// Close interface data pipe.
		e := tun.tunFile.Close()
		if err != nil {
			err = e
		}

		tun.tunFile = nil
	}

	return
}

func (tun *nativeTun) Name() (string, error) {
	return tun.wt.GetInterfaceName()
}

func (tun *nativeTun) File() *os.File {
	return nil
}

func (tun *nativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *nativeTun) Close() error {
	windows.SetEvent(tun.signals[signalClose])
	err := windows.CloseHandle(tun.signals[signalClose])

	e := tun.closeTUN()
	if err == nil {
		err = e
	}

	if tun.events != nil {
		close(tun.events)
	}

	_, _, e = tun.wt.DeleteInterface(0)
	if err == nil {
		err = e
	}

	return err
}

func (tun *nativeTun) MTU() (int, error) {
	return 1500, nil
}

func (tun *nativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}

	for {
		if tun.rdNextPacket < tun.rdBuff.numPackets {
			// Get packet from the queue.
			tunPacket := &tun.rdBuff.packets[tun.rdNextPacket]
			tun.rdNextPacket++

			if packetSizeMax < tunPacket.size {
				// Invalid packet size.
				continue
			}

			// Copy data.
			copy(buff[offset:], tunPacket.data[:tunPacket.size])
			return int(tunPacket.size), nil
		}

		if tun.signals[signalDataAvail] == 0 {
			// Data pipe and interface data available event are not open (yet).
			err := tun.openTUN()
			if err != nil {
				return 0, err
			}
		}

		// Wait for user close or interface data.
		r, err := windows.WaitForMultipleObjects(tun.signals[:], false, windows.INFINITE)
		if err != nil {
			return 0, errors.New("Waiting for data failed: " + err.Error())
		}
		switch r {
		case windows.WAIT_OBJECT_0 + signalClose, windows.WAIT_ABANDONED + signalClose:
			return 0, errors.New("TUN closed")
		case windows.WAIT_OBJECT_0 + signalDataAvail:
			// Data is available.
		case windows.WAIT_ABANDONED + signalDataAvail:
			// TUN stopped. Reopen it.
			tun.closeTUN()
			continue
		case windows.WAIT_TIMEOUT:
			// Congratulations, we reached infinity. Let's do it again! :)
			continue
		default:
			return 0, errors.New("unexpected result from WaitForMultipleObjects")
		}

		// Fill queue.
		const bufSize = int(unsafe.Sizeof(tun.rdBuff))
		n, err := tun.tunFile.Read((*[bufSize]byte)(unsafe.Pointer(&tun.rdBuff))[:])
		tun.rdNextPacket = 0
		if n != bufSize || err != nil {
			// TUN interface stopped, returned incomplete data, etc.
			// Retry.
			tun.rdBuff.numPackets = 0
			tun.closeTUN()
			continue
		}
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *nativeTun) flush() error {
	// Flush write buffer.
	const bufSize = int(unsafe.Sizeof(tun.wrBuff))
	n, err := tun.tunFile.Write((*[bufSize]byte)(unsafe.Pointer(&tun.wrBuff))[:])
	tun.wrBuff.numPackets = 0
	if err != nil {
		return err
	}
	if n != bufSize {
		return fmt.Errorf("%d byte(s) written, %d byte(s) expected", n, bufSize)
	}

	return nil
}

func (tun *nativeTun) putTunPacket(buff []byte) error {
	size := len(buff)
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > packetSizeMax {
		return errors.New("Packet too big")
	}

	if tun.wrBuff.numPackets >= packetExchangeMax {
		// Queue is full -> flush first.
		err := tun.flush()
		if err != nil {
			return err
		}
	}

	// Push packet to the buffer.
	tunPacket := &tun.wrBuff.packets[tun.wrBuff.numPackets]
	tunPacket.size = uint32(size)
	copy(tunPacket.data[:size], buff)

	tun.wrBuff.numPackets++

	return nil
}

func (tun *nativeTun) Write(buff []byte, offset int) (int, error) {
	err := tun.putTunPacket(buff[offset:])
	if err != nil {
		return 0, err
	}

	// Flush write buffer.
	return len(buff) - offset, tun.flush()
}
