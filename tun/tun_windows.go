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
	TUN_MAX_PACKET_SIZE      = 1600
	TUN_MAX_PACKET_EXCHANGE  = 256 // Number of packets that can be exchanged at a time
	TUN_EXCHANGE_BUFFER_SIZE = 410632
)

const (
	TUN_SIGNAL_DATA_AVAIL = 0
	TUN_SIGNAL_CLOSE      = 1

	TUN_SIGNAL_MAX = 2
)

type tunPacket struct {
	size uint32
	data [TUN_MAX_PACKET_SIZE]byte
}

type tunRWQueue struct {
	numPackets uint32
	packets    [TUN_MAX_PACKET_EXCHANGE]tunPacket
	left       uint32
}

type nativeTun struct {
	wt           *wintun.Wintun
	tunName      string
	signalName   *uint16
	tunFile      *os.File
	wrBuff       tunRWQueue
	rdBuff       tunRWQueue
	signals      [TUN_SIGNAL_MAX]windows.Handle
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
	tun.signals[TUN_SIGNAL_CLOSE], err = windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
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
			switch evt, e := windows.WaitForSingleObject(tun.signals[TUN_SIGNAL_CLOSE], 1000); evt {
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
		tun.signals[TUN_SIGNAL_DATA_AVAIL] = event

		return nil
	}
}

func (tun *nativeTun) closeTUN() (err error) {
	if tun.signals[TUN_SIGNAL_DATA_AVAIL] != 0 {
		// Close interface data ready event.
		e := windows.CloseHandle(tun.signals[TUN_SIGNAL_DATA_AVAIL])
		if err != nil {
			err = e
		}

		tun.signals[TUN_SIGNAL_DATA_AVAIL] = 0
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
	windows.SetEvent(tun.signals[TUN_SIGNAL_CLOSE])
	err := windows.CloseHandle(tun.signals[TUN_SIGNAL_CLOSE])

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
		for {
			if tun.rdNextPacket < tun.rdBuff.numPackets {
				// Get packet from the queue.
				tunPacket := &tun.rdBuff.packets[tun.rdNextPacket]
				tun.rdNextPacket++

				if TUN_MAX_PACKET_SIZE < tunPacket.size {
					// Invalid packet size.
					continue
				}

				// Copy data.
				copy(buff[offset:], tunPacket.data[:tunPacket.size])
				return int(tunPacket.size), nil
			}

			if tun.signals[TUN_SIGNAL_DATA_AVAIL] == 0 {
				// Data pipe and interface data available event are not open (yet).
				err := tun.openTUN()
				if err != nil {
					return 0, err
				}
			}

			if tun.rdBuff.numPackets < TUN_MAX_PACKET_EXCHANGE || tun.rdBuff.left == 0 {
				// Buffer was not full. Wait for the interface data or user close.
				r, err := windows.WaitForMultipleObjects(tun.signals[:], false, windows.INFINITE)
				if err != nil {
					return 0, errors.New("Waiting for data failed: " + err.Error())
				}
				switch r {
				case windows.WAIT_OBJECT_0 + TUN_SIGNAL_DATA_AVAIL:
					// Data is available.
				case windows.WAIT_ABANDONED + TUN_SIGNAL_DATA_AVAIL:
					// TUN stopped. Reopen it.
					tun.closeTUN()
					continue
				case windows.WAIT_OBJECT_0 + TUN_SIGNAL_CLOSE, windows.WAIT_ABANDONED + TUN_SIGNAL_CLOSE:
					return 0, errors.New("TUN closed")
				case windows.WAIT_TIMEOUT:
					// Congratulations, we reached infinity. Let's do it again! :)
					continue
				default:
					return 0, errors.New("unexpected result from WaitForMultipleObjects")
				}
			}

			// Fill queue.
			data := (*[TUN_EXCHANGE_BUFFER_SIZE]byte)(unsafe.Pointer(&tun.rdBuff))
			n, err := tun.tunFile.Read(data[:])
			tun.rdNextPacket = 0
			if n != TUN_EXCHANGE_BUFFER_SIZE || err != nil {
				// TUN interface stopped, returned incomplete data, etc.
				// Retry.
				tun.rdBuff.numPackets = 0
				tun.closeTUN()
				continue
			}
		}
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *nativeTun) flush() error {
	// Flush write buffer.
	data := (*[TUN_EXCHANGE_BUFFER_SIZE]byte)(unsafe.Pointer(&tun.wrBuff))
	n, err := tun.tunFile.Write(data[:])
	tun.wrBuff.numPackets = 0
	if err != nil {
		return err
	}
	if n != TUN_EXCHANGE_BUFFER_SIZE {
		return fmt.Errorf("%d byte(s) written, %d byte(s) expected", n, TUN_EXCHANGE_BUFFER_SIZE)
	}

	return nil
}

func (tun *nativeTun) putTunPacket(buff []byte) error {
	size := len(buff)
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > TUN_MAX_PACKET_SIZE {
		return errors.New("Packet too big")
	}

	if tun.wrBuff.numPackets >= TUN_MAX_PACKET_EXCHANGE {
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
