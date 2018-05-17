/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"./rwcancel"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

// _TUNSIFHEAD, value derived from sys/net/{if_tun,ioccom}.h
// const _TUNSIFHEAD = ((0x80000000) | (((4) & ((1 << 13) - 1) ) << 16) | (uint32(byte('t')) << 8) | (96))
const _TUNSIFHEAD = 0x80047460
const _TUNSIFMODE = 0x8004745e
const _TUNSIFPID = 0x2000745f

// Iface status string max len
const _IFSTATMAX = 800

// Structure for iface mtu get/set ioctls
type ifreq_mtu struct {
	Name [_IFNAMESIZ]byte
	MTU  uint32
	Pad0 [12]byte
}

// Structure for interface status request ioctl
type ifstat struct {
	IfsName [_IFNAMESIZ]byte
	Ascii   [_IFSTATMAX]byte
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

// Figure out the interface name for an open tun device file descriptor
func TunIfaceName(f *os.File) (string, error) {
	//Terrible hack to make up for freebsd not having a TUNGIFNAME

	fd := f.Fd()
	//First, make sure the tun pid matches this proc's pid

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(_TUNSIFPID),
		uintptr(0),
	)

	if errno != 0 {
		return "", fmt.Errorf("Failed to set tun device PID: %s", errno.Error())
	}

	// Open iface control socket

	confd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	defer unix.Close(confd)

	if err != nil {
		return "", err
	}

	procPid := os.Getpid()

	//Try to find interface with matching PID
	for i := 1; ; i++ {
		iface, _ := net.InterfaceByIndex(i)
		if err != nil || iface == nil {
			break
		}

		// Structs for getting data in and out of SIOCGIFSTATUS ioctl
		var ifstatus ifstat
		ifname := iface.Name
		copy(ifstatus.IfsName[:], ifname)

		// Make the syscall to get the status string
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(confd),
			uintptr(unix.SIOCGIFSTATUS),
			uintptr(unsafe.Pointer(&ifstatus)),
		)

		if errno != 0 {
			continue
		}

		nullStr := ifstatus.Ascii[:]
		i := bytes.IndexByte(nullStr, 0)
		if i < 1 {
			continue
		}
		if i != -1 {
			nullStr = nullStr[:i]
		}
		statStr := string(nullStr)
		var pidNum int = 0

		// Finally get the owning PID
		// Format string taken from sys/net/if_tun.c
		_, err := fmt.Sscanf(statStr, "\tOpened by PID %d\n", &pidNum)
		if err != nil {
			return "", err
		}

		if pidNum == procPid {
			return ifname, nil
		}

	}

	return "", nil
}

// Destroy a named system interface
func DestroyIface(name string) error {
	// open control socket
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
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCIFDESTROY),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("Failed to destroy interface %s: %s", name, errno.Error())
	}

	return nil
}

func CreateTUN(name string) (TUNDevice, error) {
	if len(name) > _IFNAMESIZ-1 {
		return nil, errors.New("Interface name too long")
	}

	// See if interface already exists
	iface, _ := net.InterfaceByName(name)
	if iface != nil {
		return nil, fmt.Errorf("Interface %s already exists", name)
	}

	tunfile, err := os.OpenFile("/dev/tun", unix.O_RDWR, 0)

	if err != nil {
		return nil, err
	}

	nameif, err := TunIfaceName(tunfile)

	if err != nil {
		tunfile.Close()
		return nil, err
	}

	tunfd := tunfile.Fd()

	// Enable ifhead mode, otherwise tun will complain if it gets a non-AF_INET packet
	ifheadmode := 1
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(tunfd),
		uintptr(_TUNSIFHEAD),
		uintptr(unsafe.Pointer(&ifheadmode)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("Error %s", errno.Error())
	}

	/* Set TUN iface to broadcast mode. TUN inferfaces on freebsd come up
	 * point to point by default */
	ifmodemode := unix.IFF_BROADCAST
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(tunfd),
		uintptr(_TUNSIFMODE),
		uintptr(unsafe.Pointer(&ifmodemode)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("Error %s", errno.Error())
	}

	// Rename tun interface
	// Open control socket
	ctfd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return nil, err
	}

	defer unix.Close(ctfd)

	// set up struct for iface rename
	var newnp [_IFNAMESIZ]byte
	copy(newnp[:], name)

	var ifr ifreq_ptr
	copy(ifr.Name[:], nameif)
	ifr.Data = uintptr(unsafe.Pointer(&newnp[0]))

	//do actual ioctl to rename iface
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(ctfd),
		uintptr(unix.SIOCSIFNAME),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		tunfile.Close()
		DestroyIface(name)
		return nil, fmt.Errorf("Failed to rename %s to %s: %s", nameif, name, errno.Error())
	}

	tun, err := CreateTUNFromFile(tunfile)

	if err != nil {
		return nil, err
	}

	if err == nil && name == "tun" {
		fname := os.Getenv("WG_FREEBSD_TUN_NAME_FILE")
		if fname != "" {
			os.MkdirAll(filepath.Dir(fname), 0700)
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
	name, err := TunIfaceName(tun.fd)
	if err != nil {
		return "", err
	}
	tun.name = name
	return name, nil
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
	err3 := DestroyIface(tun.name)
	close(tun.events)
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
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
	var ifr ifreq_mtu
	copy(ifr.Name[:], tun.name)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get MTU on %s", tun.name)
	}

	// convert result to signed 32-bit int
	mtu := ifr.MTU
	if mtu >= (1 << 31) {
		return int(mtu-(1<<31)) - (1 << 31), nil
	}
	return int(mtu), nil

}
