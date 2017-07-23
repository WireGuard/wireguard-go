/* Copyright (c) 2016, Song Gao <song@gao.io>
 * All rights reserved.
 *
 * Code from https://github.com/songgao/water
 */

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"sync"
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

var sockaddrCtlSize uintptr = 32

func CreateTUN(name string) (ifce TUNDevice, err error) {
	ifIndex := -1
	fmt.Sscanf(name, "utun%d", &ifIndex)
	if ifIndex < 0 {
		return nil, fmt.Errorf("error parsing interface name %s, must be utun[0-9]+", name)
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)

	if err != nil {
		return nil, fmt.Errorf("error in unix.Socket: %v", err)
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
		err = errno
		return nil, fmt.Errorf("error in unix.Syscall(unix.SYS_IOTL, ...): %v", err)
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
		err = errno
		return nil, fmt.Errorf("error in unix.RawSyscall(unix.SYS_CONNECT, ...): %v", err)
	}

	// read (new) name of interface

	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(16)

	_, _, errno = unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		2, /* #define SYSPROTO_CONTROL 2 */
		2, /* #define UTUN_OPT_IFNAME 2 */
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0)

	if errno != 0 {
		err = errno
		return nil, fmt.Errorf("error in unix.Syscall6(unix.SYS_GETSOCKOPT, ...): %v", err)
	}

	device := &tunReadCloser{
		name: string(ifName.name[:ifNameSize-1 /* -1 is for \0 */]),
		f:    os.NewFile(uintptr(fd), string(ifName.name[:])),
		mtu:  1500,
	}

	// set default MTU

	err = device.setMTU(DefaultMTU)

	return device, err
}

// tunReadCloser is a hack to work around the first 4 bytes "packet
// information" because there doesn't seem to be an IFF_NO_PI for darwin.
type tunReadCloser struct {
	name string
	f    io.ReadWriteCloser
	mtu  int

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

var _ io.ReadWriteCloser = (*tunReadCloser)(nil)

func (t *tunReadCloser) Read(to []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	if cap(t.rBuf) < len(to)+4 {
		t.rBuf = make([]byte, len(to)+4)
	}
	t.rBuf = t.rBuf[:len(to)+4]

	n, err := t.f.Read(t.rBuf)
	copy(to, t.rBuf[4:])
	return n - 4, err
}

func (t *tunReadCloser) Write(from []byte) (int, error) {

	if len(from) == 0 {
		return 0, unix.EIO
	}

	t.wMu.Lock()
	defer t.wMu.Unlock()

	if cap(t.wBuf) < len(from)+4 {
		t.wBuf = make([]byte, len(from)+4)
	}
	t.wBuf = t.wBuf[:len(from)+4]

	// determine the IP Family for the NULL L2 Header

	ipVer := from[0] >> 4
	if ipVer == ipv4.Version {
		t.wBuf[3] = unix.AF_INET
	} else if ipVer == ipv6.Version {
		t.wBuf[3] = unix.AF_INET6
	} else {
		return 0, errors.New("Unable to determine IP version from packet.")
	}

	copy(t.wBuf[4:], from)

	n, err := t.f.Write(t.wBuf)
	return n - 4, err
}

func (t *tunReadCloser) Close() error {

	// lock to make sure no read/write is in process.

	t.rMu.Lock()
	defer t.rMu.Unlock()

	t.wMu.Lock()
	defer t.wMu.Unlock()

	return t.f.Close()
}

func (t *tunReadCloser) Name() string {
	return t.name
}

func (t *tunReadCloser) setMTU(n int) error {

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
	copy(ifr[:], t.name)
	binary.LittleEndian.PutUint32(ifr[16:20], uint32(n))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("Failed to set MTU on %s", t.name)
	}

	return nil
}

func (t *tunReadCloser) MTU() (int, error) {

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
	copy(ifr[:], t.name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get MTU on %s", t.name)
	}

	// convert result to signed 32-bit int

	val := binary.LittleEndian.Uint32(ifr[16:20])
	if val >= (1 << 31) {
		return int(val-(1<<31)) - (1 << 31), nil
	}
	return int(val), nil
}
