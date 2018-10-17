/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"git.zx2c4.com/wireguard-go/rwcancel"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// Structure for iface mtu get/set ioctls
type ifreq_mtu struct {
	Name [unix.IFNAMSIZ]byte
	MTU  uint32
	Pad0 [12]byte
}

const _TUNSIFMODE = 0x8004745d

type nativeTun struct {
	name        string
	tunFile     *os.File
	rwcancel    *rwcancel.RWCancel
	events      chan TUNEvent
	errors      chan error
	routeSocket int
}

func (tun *nativeTun) routineRouteListener(tunIfindex int) {
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

		if n < 8 {
			continue
		}

		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[6 /* ifindex */])))
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
			tun.events <- TUNEventUp
		}
		if up != statusUp && !up {
			tun.events <- TUNEventDown
		}
		statusUp = up

		// MTU changes
		if iface.MTU != statusMTU {
			tun.events <- TUNEventMTUUpdate
		}
		statusMTU = iface.MTU
	}
}

func errorIsEBUSY(err error) bool {
	if pe, ok := err.(*os.PathError); ok {
		err = pe.Err
	}
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.EBUSY {
		return true
	}
	return false
}

func CreateTUN(name string, mtu int) (TUNDevice, error) {
	ifIndex := -1
	if name != "tun" {
		_, err := fmt.Sscanf(name, "tun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be tun[0-9]*")
		}
	}

	var tunfile *os.File
	var err error

	if ifIndex != -1 {
		tunfile, err = os.OpenFile(fmt.Sprintf("/dev/tun%d", ifIndex), unix.O_RDWR, 0)
	} else {
		for ifIndex = 0; ifIndex < 256; ifIndex += 1 {
			tunfile, err = os.OpenFile(fmt.Sprintf("/dev/tun%d", ifIndex), unix.O_RDWR, 0)
			if err == nil || !errorIsEBUSY(err) {
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}

	tun, err := CreateTUNFromFile(tunfile, mtu)

	if err == nil && name == "tun" {
		fname := os.Getenv("WG_TUN_NAME_FILE")
		if fname != "" {
			ioutil.WriteFile(fname, []byte(tun.(*nativeTun).name+"\n"), 0400)
		}
	}

	return tun, err
}

func CreateTUNFromFile(file *os.File, mtu int) (TUNDevice, error) {

	tun := &nativeTun{
		tunFile: file,
		events:  make(chan TUNEvent, 10),
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

	tun.rwcancel, err = rwcancel.NewRWCancel(int(file.Fd()))
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

func (tun *nativeTun) Name() (string, error) {
	gostat, err := tun.tunFile.Stat()
	if err != nil {
		tun.name = ""
		return "", err
	}
	stat := gostat.Sys().(*syscall.Stat_t)
	tun.name = fmt.Sprintf("tun%d", stat.Rdev%256)
	return tun.name, nil
}

func (tun *nativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *nativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *nativeTun) doRead(buff []byte, offset int) (int, error) {
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

func (tun *nativeTun) Read(buff []byte, offset int) (int, error) {
	for {
		n, err := tun.doRead(buff, offset)
		if err == nil || !rwcancel.RetryAfterError(err) {
			return n, err
		}
		if !tun.rwcancel.ReadyRead() {
			return 0, errors.New("tun device closed")
		}
	}
}

func (tun *nativeTun) Write(buff []byte, offset int) (int, error) {

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

func (tun *nativeTun) Close() error {
	var err3 error
	err1 := tun.rwcancel.Cancel()
	err2 := tun.tunFile.Close()
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

func (tun *nativeTun) setMTU(n int) error {
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

func (tun *nativeTun) MTU() (int, error) {
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
