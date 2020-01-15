/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
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

type NativeTun struct {
	name        string
	tunFile     *os.File
	events      chan Event
	errors      chan error
	routeSocket int
}

var sockaddrCtlSize uintptr = 32

func retryInterfaceByIndex(index int) (iface *net.Interface, err error) {
	for i := 0; i < 20; i++ {
		iface, err = net.InterfaceByIndex(index)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok {
				if syscallErr, ok := opErr.Err.(*os.SyscallError); ok && syscallErr.Err == syscall.ENOMEM {
					time.Sleep(time.Duration(i) * time.Second / 3)
					continue
				}
			}
		}
		return iface, err
	}
	return nil, err
}

func (tun *NativeTun) routineRouteListener(tunIfindex int) {
	var (
		statusUp  bool
		statusMTU int
	)

	defer close(tun.events)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(tun.routeSocket, data)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINTR {
				goto retry
			}
			tun.errors <- err
			return
		}

		if n < 14 {
			continue
		}

		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}

		iface, err := retryInterfaceByIndex(ifindex)
		if err != nil {
			tun.errors <- err
			return
		}

		// Up / Down event
		up := (iface.Flags & net.FlagUp) != 0
		if up != statusUp && up {
			tun.events <- EventUp
		}
		if up != statusUp && !up {
			tun.events <- EventDown
		}
		statusUp = up

		// MTU changes
		if iface.MTU != statusMTU {
			tun.events <- EventMTUUpdate
		}
		statusMTU = iface.MTU
	}
}

func CreateTUN(name string, mtu int) (Device, error) {
	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
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

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	tun, err := CreateTUNFromFile(os.NewFile(uintptr(fd), ""), mtu)

	if err == nil && name == "utun" {
		fname := os.Getenv("WG_TUN_NAME_FILE")
		if fname != "" {
			ioutil.WriteFile(fname, []byte(tun.(*NativeTun).name+"\n"), 0400)
		}
	}

	return tun, err
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 5),
	}

	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return -1, err
		}
		return iface.Index, nil
	}()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	tun.routeSocket, err = unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	go tun.routineRouteListener(tunIfindex)

	if mtu > 0 {
		err = tun.setMTU(mtu)
		if err != nil {
			tun.Close()
			return nil, err
		}
	}

	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(16)

	var errno syscall.Errno
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			2, /* #define SYSPROTO_CONTROL 2 */
			2, /* #define UTUN_OPT_IFNAME 2 */
			uintptr(unsafe.Pointer(&ifName)),
			uintptr(unsafe.Pointer(&ifNameSize)), 0)
	})

	if errno != 0 {
		return "", fmt.Errorf("SYS_GETSOCKOPT: %v", errno)
	}

	tun.name = string(ifName.name[:ifNameSize-1])
	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		buff := buff[offset-4:]
		n, err := tun.tunFile.Read(buff[:])
		if n < 4 {
			return 0, err
		}
		return n - 4, err
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

	return tun.tunFile.Write(buff)
}

func (tun *NativeTun) Flush() error {
	// TODO: can flushing be implemented by buffering and using sendmmsg?
	return nil
}

func (tun *NativeTun) Close() error {
	var err2 error
	err1 := tun.tunFile.Close()
	if tun.routeSocket != -1 {
		unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
		err2 = unix.Close(tun.routeSocket)
	} else if tun.events != nil {
		close(tun.events)
	}
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
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU on %s", tun.name)
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
		return 0, fmt.Errorf("failed to get MTU on %s", tun.name)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[16]))), nil
}
