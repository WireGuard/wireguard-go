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
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)

type rateJuggler struct {
	current       uint64
	nextByteCount uint64
	nextStartTime int64
	changing      int32
}

type NativeTun struct {
	wt        *wintun.Interface
	handle    windows.Handle
	close     bool
	events    chan Event
	errors    chan error
	forcedMTU int
	rate      rateJuggler
	rings     *wintun.RingDescriptor
	writeLock sync.Mutex
}

const WintunPool = wintun.Pool("WireGuard")

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

//
// CreateTUN creates a Wintun interface with the given name. Should a Wintun
// interface with the same name exist, it is reused.
//
func CreateTUN(ifname string, mtu int) (Device, error) {
	return CreateTUNWithRequestedGUID(ifname, nil, mtu)
}

//
// CreateTUNWithRequestedGUID creates a Wintun interface with the given name and
// a requested GUID. Should a Wintun interface with the same name exist, it is reused.
//
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID, mtu int) (Device, error) {
	var err error
	var wt *wintun.Interface

	// Does an interface with this name already exist?
	wt, err = WintunPool.GetInterface(ifname)
	if err == nil {
		// If so, we delete it, in case it has weird residual configuration.
		_, err = wt.DeleteInterface()
		if err != nil {
			return nil, fmt.Errorf("Error deleting already existing interface: %v", err)
		}
	}
	wt, _, err = WintunPool.CreateInterface(ifname, requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Error creating interface: %v", err)
	}

	forcedMTU := 1420
	if mtu > 0 {
		forcedMTU = mtu
	}

	tun := &NativeTun{
		wt:        wt,
		handle:    windows.InvalidHandle,
		events:    make(chan Event, 10),
		errors:    make(chan error, 1),
		forcedMTU: forcedMTU,
	}

	tun.rings, err = wintun.NewRingDescriptor()
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("Error creating events: %v", err)
	}

	tun.handle, err = tun.wt.Register(tun.rings)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("Error registering rings: %v", err)
	}
	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.wt.Name()
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	tun.close = true
	if tun.rings.Send.TailMoved != 0 {
		windows.SetEvent(tun.rings.Send.TailMoved) // wake the reader if it's sleeping
	}
	if tun.handle != windows.InvalidHandle {
		windows.CloseHandle(tun.handle)
	}
	tun.rings.Close()
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

	buffHead := atomic.LoadUint32(&tun.rings.Send.Ring.Head)
	if buffHead >= wintun.PacketCapacity {
		return 0, os.ErrClosed
	}

	start := nanotime()
	shouldSpin := atomic.LoadUint64(&tun.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&tun.rate.nextStartTime)) <= rateMeasurementGranularity*2
	var buffTail uint32
	for {
		buffTail = atomic.LoadUint32(&tun.rings.Send.Ring.Tail)
		if buffHead != buffTail {
			break
		}
		if tun.close {
			return 0, os.ErrClosed
		}
		if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
			windows.WaitForSingleObject(tun.rings.Send.TailMoved, windows.INFINITE)
			goto retry
		}
		procyield(1)
	}
	if buffTail >= wintun.PacketCapacity {
		return 0, os.ErrClosed
	}

	buffContent := tun.rings.Send.Ring.Wrap(buffTail - buffHead)
	if buffContent < uint32(unsafe.Sizeof(wintun.PacketHeader{})) {
		return 0, errors.New("incomplete packet header in send ring")
	}

	packet := (*wintun.Packet)(unsafe.Pointer(&tun.rings.Send.Ring.Data[buffHead]))
	if packet.Size > wintun.PacketSizeMax {
		return 0, errors.New("packet too big in send ring")
	}

	alignedPacketSize := wintun.PacketAlign(uint32(unsafe.Sizeof(wintun.PacketHeader{})) + packet.Size)
	if alignedPacketSize > buffContent {
		return 0, errors.New("incomplete packet in send ring")
	}

	copy(buff[offset:], packet.Data[:packet.Size])
	buffHead = tun.rings.Send.Ring.Wrap(buffHead + alignedPacketSize)
	atomic.StoreUint32(&tun.rings.Send.Ring.Head, buffHead)
	tun.rate.update(uint64(packet.Size))
	return int(packet.Size), nil
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
	alignedPacketSize := wintun.PacketAlign(uint32(unsafe.Sizeof(wintun.PacketHeader{})) + packetSize)

	tun.writeLock.Lock()
	defer tun.writeLock.Unlock()

	buffHead := atomic.LoadUint32(&tun.rings.Receive.Ring.Head)
	if buffHead >= wintun.PacketCapacity {
		return 0, os.ErrClosed
	}

	buffTail := atomic.LoadUint32(&tun.rings.Receive.Ring.Tail)
	if buffTail >= wintun.PacketCapacity {
		return 0, os.ErrClosed
	}

	buffSpace := tun.rings.Receive.Ring.Wrap(buffHead - buffTail - wintun.PacketAlignment)
	if alignedPacketSize > buffSpace {
		return 0, nil // Dropping when ring is full.
	}

	packet := (*wintun.Packet)(unsafe.Pointer(&tun.rings.Receive.Ring.Data[buffTail]))
	packet.Size = packetSize
	copy(packet.Data[:packetSize], buff[offset:])
	atomic.StoreUint32(&tun.rings.Receive.Ring.Tail, tun.rings.Receive.Ring.Wrap(buffTail+alignedPacketSize))
	if atomic.LoadInt32(&tun.rings.Receive.Ring.Alertable) != 0 {
		windows.SetEvent(tun.rings.Receive.TailMoved)
	}
	return int(packetSize), nil
}

// LUID returns Windows interface instance ID.
func (tun *NativeTun) LUID() uint64 {
	return tun.wt.LUID()
}

// Version returns the version of the Wintun driver and NDIS system currently loaded.
func (tun *NativeTun) Version() (driverVersion string, ndisVersion string, err error) {
	return tun.wt.Version()
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
