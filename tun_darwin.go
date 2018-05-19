/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

package main

import (
	"./rwcancel"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"net"
	"os"
	"time"
	"unsafe"
)

const utunControlName = "com.apple.net.utun_control"

// _CTLIOCGINFO value derived from /usr/include/sys/{kern_control,ioccom}.h
const _CTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

// sockaddr_ctl specifeid in /usr/include/sys/kern_control.h
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// NativeTun is a hack to work around the first 4 bytes "packet
// information" because there doesn't seem to be an IFF_NO_PI for darwin.
type NativeTun struct {
	name                    string
	fd                      *os.File
	rwcancel                *rwcancel.RWCancel
	mtu                     int
	events                  chan TUNEvent
	errors                  chan error
	statusListenersShutdown chan struct{}
}

var sockaddrCtlSize uintptr = 32

func CreateTUN(name string) (TUNDevice, error) {
	ifIndex := -1
	if name != "utun" {
		fmt.Sscanf(name, "utun%d", &ifIndex)
		if ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be utun[0-9]*")
		}
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)

	if err != nil {
		return nil, err
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}

	copy(ctlInfo.ctlName[:], []byte(utunControlName))

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(_CTLIOCGINFO),
		uintptr(unsafe.Pointer(ctlInfo)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("_CTLIOCGINFO: %v", errno)
	}

	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: 2,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}

	scPointer := unsafe.Pointer(&sc)

	_, _, errno = unix.RawSyscall(
		unix.SYS_CONNECT,
		uintptr(fd),
		uintptr(scPointer),
		uintptr(sockaddrCtlSize),
	)

	if errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	tun, err := CreateTUNFromFile(os.NewFile(uintptr(fd), ""))

	if err == nil && name == "utun" {
		fname := os.Getenv("WG_DARWIN_UTUN_NAME_FILE")
		if fname != "" {
			ioutil.WriteFile(fname, []byte(tun.(*NativeTun).name+"\n"), 0400)
		}
	}

	return tun, err
}

func CreateTUNFromFile(file *os.File) (TUNDevice, error) {

	tun := &NativeTun{
		fd:                      file,
		mtu:                     1500,
		events:                  make(chan TUNEvent, 10),
		errors:                  make(chan error, 1),
		statusListenersShutdown: make(chan struct{}),
	}

	_, err := tun.Name()
	if err != nil {
		tun.fd.Close()
		return nil, err
	}

	tun.rwcancel, err = rwcancel.NewRWCancel(int(file.Fd()))
	if err != nil {
		tun.fd.Close()
		return nil, err
	}

	// TODO: Fix this very naive implementation
	go func(tun *NativeTun) {
		var (
			statusUp  bool
			statusMTU int
		)

		for {
			intr, err := net.InterfaceByName(tun.name)
			if err != nil {
				tun.errors <- err
				return
			}

			// Up / Down event
			up := (intr.Flags & net.FlagUp) != 0
			if up != statusUp && up {
				tun.events <- TUNEventUp
			}
			if up != statusUp && !up {
				tun.events <- TUNEventDown
			}
			statusUp = up

			// MTU changes
			if intr.MTU != statusMTU {
				tun.events <- TUNEventMTUUpdate
			}
			statusMTU = intr.MTU

			select {
			case <-time.After(time.Second / 10):
			case <-tun.statusListenersShutdown:
				return
			}
		}
	}(tun)

	// set default MTU
	err = tun.setMTU(DefaultMTU)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {

	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(16)

	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(tun.fd.Fd()),
		2, /* #define SYSPROTO_CONTROL 2 */
		2, /* #define UTUN_OPT_IFNAME 2 */
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0)

	if errno != 0 {
		return "", fmt.Errorf("SYS_GETSOCKOPT: %v", errno)
	}

	tun.name = string(ifName.name[:ifNameSize-1])
	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return tun.fd
}

func (tun *NativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *NativeTun) doRead(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		buff := buff[offset-4:]
		n, err := tun.fd.Read(buff[:])
		if n < 4 {
			return 0, err
		}
		return n - 4, err
	}
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	for {
		n, err := tun.doRead(buff, offset)
		if err == nil || !rwcancel.ErrorIsEAGAIN(err) {
			return n, err
		}
		if !tun.rwcancel.ReadyRead() {
			return 0, errors.New("tun device closed")
		}
	}
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {

	// reserve space for header

	buff = buff[offset-4:]

	// add packet information header

	buff[0] = 0x00
	buff[1] = 0x00
	buff[2] = 0x00

	if buff[4]>>4 == ipv6.Version {
		buff[3] = unix.AF_INET6
	} else {
		buff[3] = unix.AF_INET
	}

	// write

	return tun.fd.Write(buff)
}

func (tun *NativeTun) Close() error {
	close(tun.statusListenersShutdown)
	err1 := tun.rwcancel.Cancel()
	err2 := tun.fd.Close()
	close(tun.events)
	if err1 != nil {
		return err1
	}
	return err2
}

func (tun *NativeTun) setMTU(n int) error {

	// open datagram socket

	var fd int

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [32]byte
	copy(ifr[:], tun.name)
	binary.LittleEndian.PutUint32(ifr[16:20], uint32(n))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("Failed to set MTU on %s", tun.name)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {

	// open datagram socket

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [64]byte
	copy(ifr[:], tun.name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get MTU on %s", tun.name)
	}

	// convert result to signed 32-bit int

	val := binary.LittleEndian.Uint32(ifr[16:20])
	if val >= (1 << 31) {
		return int(val-(1<<31)) - (1 << 31), nil
	}
	return int(val), nil
}
