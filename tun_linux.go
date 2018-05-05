/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/* Copyright 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

package main

/* Implementation of the TUN device interface for linux
 */

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type NativeTun struct {
	fd            *os.File
	index         int32         // if index
	name          string        // name of interface
	errors        chan error    // async error handling
	events        chan TUNEvent // device related events
	nopi          bool          // the device was pased IFF_NO_PI
	closingReader *os.File
	closingWriter *os.File
}

func (tun *NativeTun) File() *os.File {
	return tun.fd
}

func (tun *NativeTun) RoutineHackListener() {
	// TODO: This function never actually exits in response to anything,
	// a go routine that goes forever. We'll want to fix that if this is
	// to ever be used as any sort of library.

	/* This is needed for the detection to work across network namespaces
	 * If you are reading this and know a better method, please get in touch.
	 */
	fd := int(tun.fd.Fd())
	for {
		_, err := unix.Write(fd, nil)
		switch err {
		case unix.EINVAL:
			tun.events <- TUNEventUp
		case unix.EIO:
			tun.events <- TUNEventDown
		default:
		}
		time.Sleep(time.Second / 10)
	}
}

func toRTMGRP(sc uint) uint {
	return 1 << (sc - 1)
}

func (tun *NativeTun) RoutineNetlinkListener() {

	groups := toRTMGRP(unix.RTNLGRP_LINK)
	groups |= toRTMGRP(unix.RTNLGRP_IPV4_IFADDR)
	groups |= toRTMGRP(unix.RTNLGRP_IPV6_IFADDR)
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		tun.errors <- errors.New("Failed to create netlink event listener socket")
		return
	}
	defer unix.Close(sock)
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: uint32(groups),
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		tun.errors <- errors.New("Failed to bind netlink event listener socket")
		return
	}

	// TODO: This function never actually exits in response to anything,
	// a go routine that goes forever. We'll want to fix that if this is
	// to ever be used as any sort of library. See what we've done with
	// calling shutdown() on the netlink socket in conn_linux.go, and
	// change this to be more like that.

	for msg := make([]byte, 1<<16); ; {

		msgn, _, _, _, err := unix.Recvmsg(sock, msg[:], nil, 0)
		if err != nil {
			tun.errors <- fmt.Errorf("Failed to receive netlink message: %s", err.Error())
			return
		}

		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if int(hdr.Len) > len(remain) {
				break
			}

			switch hdr.Type {
			case unix.NLMSG_DONE:
				remain = []byte{}

			case unix.RTM_NEWLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[hdr.Len:]

				if info.Index != tun.index {
					// not our interface
					continue
				}

				if info.Flags&unix.IFF_RUNNING != 0 {
					tun.events <- TUNEventUp
				}

				if info.Flags&unix.IFF_RUNNING == 0 {
					tun.events <- TUNEventDown
				}

				tun.events <- TUNEventMTUUpdate

			default:
				remain = remain[hdr.Len:]
			}
		}
	}
}

func (tun *NativeTun) isUp() (bool, error) {
	inter, err := net.InterfaceByName(tun.name)
	return inter.Flags&net.FlagUp != 0, err
}

func getDummySock() (int, error) {
	return unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
}

func getIFIndex(name string) (int32, error) {
	fd, err := getDummySock()
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return 0, errno
	}

	index := binary.LittleEndian.Uint32(ifr[unix.IFNAMSIZ:])
	return toInt32(index), nil
}

func (tun *NativeTun) setMTU(n int) error {

	// open datagram socket

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

	var ifr [ifReqSize]byte
	copy(ifr[:], tun.name)
	binary.LittleEndian.PutUint32(ifr[16:20], uint32(n))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return errors.New("Failed to set MTU of TUN device")
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

	var ifr [ifReqSize]byte
	copy(ifr[:], tun.name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, errors.New("Failed to get MTU of TUN device: " + strconv.FormatInt(int64(errno), 10))
	}

	// convert result to signed 32-bit int

	val := binary.LittleEndian.Uint32(ifr[16:20])
	if val >= (1 << 31) {
		return int(toInt32(val)), nil
	}
	return int(val), nil
}

func (tun *NativeTun) Name() (string, error) {

	var ifr [ifReqSize]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		tun.fd.Fd(),
		uintptr(unix.TUNGETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return "", errors.New("Failed to get name of TUN device: " + strconv.FormatInt(int64(errno), 10))
	}
	nullStr := ifr[:]
	i := bytes.IndexByte(nullStr, 0)
	if i != -1 {
		nullStr = nullStr[:i]
	}
	tun.name = string(nullStr)
	return tun.name, nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {

	if tun.nopi {
		buff = buff[offset:]
	} else {
		// reserve space for header

		buff = buff[offset-4:]

		// add packet information header

		buff[0] = 0x00
		buff[1] = 0x00

		if buff[4]>>4 == ipv6.Version {
			buff[2] = 0x86
			buff[3] = 0xdd
		} else {
			buff[2] = 0x08
			buff[3] = 0x00
		}
	}

	// write

	return tun.fd.Write(buff)
}

type FdSet struct {
	fdset unix.FdSet
}

func (fdset *FdSet) set(i int) {
	bits := 32 << (^uint(0) >> 63)
	fdset.fdset.Bits[i/bits] |= 1 << uint(i%bits)
}

func (fdset *FdSet) check(i int) bool {
	bits := 32 << (^uint(0) >> 63)
	return (fdset.fdset.Bits[i/bits] & (1 << uint(i%bits))) != 0
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (tun *NativeTun) readyRead() bool {
	readFd := int(tun.fd.Fd())
	closeFd := int(tun.closingReader.Fd())
	fdset := FdSet{}
	fdset.set(readFd)
	fdset.set(closeFd)
	_, err := unix.Select(max(readFd, closeFd)+1, &fdset.fdset, nil, nil, nil)
	if err != nil {
		return false
	}
	if fdset.check(closeFd) {
		return false
	}
	return fdset.check(readFd)
}

func (tun *NativeTun) doRead(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		if tun.nopi {
			return tun.fd.Read(buff[offset:])
		} else {
			buff := buff[offset-4:]
			n, err := tun.fd.Read(buff[:])
			if n < 4 {
				return 0, err
			}
			return n - 4, err
		}
	}
}

func unixIsEAGAIN(err error) bool {
	if pe, ok := err.(*os.PathError); ok {
		if errno, ok := pe.Err.(syscall.Errno); ok && errno == syscall.EAGAIN {
			return true
		}
	}
	return false
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	for {
		n, err := tun.doRead(buff, offset)
		if err == nil || !unixIsEAGAIN(err) {
			return n, err
		}
		if !tun.readyRead() {
			return 0, errors.New("Tun device closed")
		}
	}
}

func (tun *NativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *NativeTun) Close() error {
	err := tun.fd.Close()
	if err != nil {
		return err
	}
	tun.closingWriter.Write([]byte{0})
	return nil
}

func CreateTUNFromFile(fd *os.File) (TUNDevice, error) {
	device := &NativeTun{
		fd:     fd,
		events: make(chan TUNEvent, 5),
		errors: make(chan error, 5),
		nopi:   false,
	}
	var err error

	err = syscall.SetNonblock(int(fd.Fd()), true)
	if err != nil {
		return nil, err
	}

	_, err = device.Name()
	if err != nil {
		return nil, err
	}

	device.closingReader, device.closingWriter, err = os.Pipe()
	if err != nil {
		return nil, err
	}

	// start event listener

	device.index, err = getIFIndex(device.name)
	if err != nil {
		return nil, err
	}

	go device.RoutineNetlinkListener()
	go device.RoutineHackListener() // cross namespace

	// set default MTU

	return device, device.setMTU(DefaultMTU)
}

func CreateTUN(name string) (TUNDevice, error) {

	// open clone device

	// HACK: we open it as a raw Fd first, so that f.nonblock=false
	// when we make it into a file object.
	nfd, err := syscall.Open(cloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	err = syscall.SetNonblock(nfd, true)
	if err != nil {
		return nil, err
	}

	fd := os.NewFile(uintptr(nfd), cloneDevicePath)
	if err != nil {
		return nil, err
	}

	// create new device

	var ifr [ifReqSize]byte
	var flags uint16 = unix.IFF_TUN // | unix.IFF_NO_PI (disabled for TUN status hack)
	nameBytes := []byte(name)
	if len(nameBytes) >= unix.IFNAMSIZ {
		return nil, errors.New("Interface name too long")
	}
	copy(ifr[:], nameBytes)
	binary.LittleEndian.PutUint16(ifr[16:], flags)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		fd.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return nil, errno
	}

	// read (new) name of interface

	newName := string(ifr[:])
	newName = newName[:strings.Index(newName, "\000")]
	device := &NativeTun{
		fd:     fd,
		name:   newName,
		events: make(chan TUNEvent, 5),
		errors: make(chan error, 5),
		nopi:   false,
	}

	device.closingReader, device.closingWriter, err = os.Pipe()
	if err != nil {
		return nil, err
	}

	// start event listener

	device.index, err = getIFIndex(device.name)
	if err != nil {
		return nil, err
	}

	go device.RoutineNetlinkListener()
	go device.RoutineHackListener() // cross namespace

	// set default MTU

	return device, device.setMTU(DefaultMTU)
}
