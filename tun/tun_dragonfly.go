/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020-2021 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)


// IOCTL numbers derived from <sys/net/tun/if_tun.h> (print them in C)
const (
	_TUNSIFHEAD = 0x80047460  // _IOW('t', 96, int)
	_TUNGIFNAME = 0x40207462  // _IOR('t', 98, struct ifreq)
)

// Iface status string max len
const _IFSTATMAX = 800

const SIZEOF_UINTPTR = 4 << (^uintptr(0) >> 32 & 1)

// structure for iface requests with a pointer
type ifreq_ptr struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
	Pad0 [16 - SIZEOF_UINTPTR]byte
}

// Structure for iface mtu get/set ioctls
type ifreq_mtu struct {
	Name [unix.IFNAMSIZ]byte
	MTU  uint32
	Pad0 [12]byte
}

// Structure for interface status request ioctl
type ifstat struct {
	IfsName [unix.IFNAMSIZ]byte
	Ascii   [_IFSTATMAX]byte
}

type NativeTun struct {
	name        string
	tunFile     *os.File
	events      chan Event
	errors      chan error
	routeSocket int
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
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[4 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}

		iface, err := net.InterfaceByIndex(ifindex)
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

func tunName(fd uintptr) (string, error) {
	var ifr ifreq_ptr;
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(_TUNGIFNAME),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return "", errors.New("failed to get name of TUN device: " + errno.Error())
	}

	name := ifr.Name[:]
	if i := bytes.IndexByte(name, 0); i != -1 {
		name = name[:i]
	}
	return string(name), nil
}

func tunDestroy(name string) error {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr [unix.IFNAMSIZ]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCIFDESTROY),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return fmt.Errorf("failed to destroy interface %s: %s", name, errno.Error())
	}

	return nil
}

func CreateTUN(name string, mtu int) (Device, error) {
	if len(name) > unix.IFNAMSIZ-1 {
		return nil, errors.New("interface name too long")
	}

	iface, _ := net.InterfaceByName(name)
	if iface != nil {
		return nil, fmt.Errorf("interface %s already exists", name)
	}

	tunFile, err := os.OpenFile("/dev/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	tun := NativeTun{tunFile: tunFile}
	var assignedName string
	tun.operateOnFd(func(fd uintptr) {
		assignedName, err = tunName(fd)
	})
	if err != nil {
		tunFile.Close()
		return nil, err
	}

	// Enable ifhead mode, otherwise tun will complain if it gets a non-AF_INET packet
	ifheadmode := 1
	var errno syscall.Errno
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(_TUNSIFHEAD),
			uintptr(unsafe.Pointer(&ifheadmode)),
		)
	})
	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to put into IFHEAD mode: %v", errno)
	}

	// Rename tun interface

	confd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer unix.Close(confd)

	var newnp [unix.IFNAMSIZ]byte
	copy(newnp[:], name)

	var ifr ifreq_ptr
	copy(ifr.Name[:], assignedName)
	ifr.Data = uintptr(unsafe.Pointer(&newnp[0]))

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(confd),
		uintptr(unix.SIOCSIFNAME),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("failed to rename %s to %s: %v", assignedName, name, errno)
	}

	return CreateTUNFromFile(tunFile, mtu)
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
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

	err = tun.setMTU(mtu)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	var name string
	var err error
	tun.operateOnFd(func(fd uintptr) {
		name, err = tunName(fd)
	})
	if err != nil {
		return "", err
	}

	tun.name = name
	return name, nil
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

	return tun.tunFile.Write(buff)
}

func (tun *NativeTun) Flush() error {
	// TODO: can flushing be implemented by buffering and using sendmmsg?
	return nil
}

func (tun *NativeTun) Close() error {
	var err3 error
	err1 := tun.tunFile.Close()
	err2 := tunDestroy(tun.name)
	if tun.routeSocket != -1 {
		unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
		err3 = unix.Close(tun.routeSocket)
		tun.routeSocket = -1
	} else if tun.events != nil {
		close(tun.events)
	}
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (tun *NativeTun) setMTU(n int) error {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr ifreq_mtu
	copy(ifr.Name[:], tun.name)
	ifr.MTU = uint32(n)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to set MTU on %s", tun.name)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var ifr ifreq_mtu
	copy(ifr.Name[:], tun.name)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU on %s", tun.name)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr.MTU))), nil
}
