/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

/* Copyright 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

package main

/* Implementation of the TUN device interface for linux
 */

import (
	"./rwcancel"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type NativeTun struct {
	fd                      *os.File
	fdCancel                *rwcancel.RWCancel
	index                   int32         // if index
	name                    string        // name of interface
	errors                  chan error    // async error handling
	events                  chan TUNEvent // device related events
	nopi                    bool          // the device was pased IFF_NO_PI
	netlinkSock             int
	netlinkCancel           *rwcancel.RWCancel
	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}
}

func (tun *NativeTun) File() *os.File {
	return tun.fd
}

func (tun *NativeTun) RoutineHackListener() {
	defer tun.hackListenerClosed.Unlock()
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
			return
		}
		select {
		case <-time.After(time.Second):
		case <-tun.statusListenersShutdown:
			return
		}
	}
}

func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: uint32((1 << (unix.RTNLGRP_LINK - 1)) | (1 << (unix.RTNLGRP_IPV4_IFADDR - 1)) | (1 << (unix.RTNLGRP_IPV6_IFADDR - 1))),
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		return -1, err
	}
	return sock, nil
}

func (tun *NativeTun) RoutineNetlinkListener() {
	defer func() {
		unix.Close(tun.netlinkSock)
		tun.hackListenerClosed.Lock()
		close(tun.events)
	}()

	for msg := make([]byte, 1<<16); ; {

		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.ErrorIsEAGAIN(err) {
				break
			}
			if !tun.netlinkCancel.ReadyRead() {
				tun.errors <- fmt.Errorf("netlink socket closed: %s", err.Error())
				return
			}
		}
		if err != nil {
			tun.errors <- fmt.Errorf("failed to receive netlink message: %s", err.Error())
			return
		}

		select {
		case <-tun.statusListenersShutdown:
			return
		default:
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
		return errors.New("failed to set MTU of TUN device")
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
		return 0, errors.New("failed to get MTU of TUN device: " + strconv.FormatInt(int64(errno), 10))
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
		return "", errors.New("failed to get name of TUN device: " + strconv.FormatInt(int64(errno), 10))
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

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	for {
		n, err := tun.doRead(buff, offset)
		if err == nil || !rwcancel.ErrorIsEAGAIN(err) {
			return n, err
		}
		if !tun.fdCancel.ReadyRead() {
			return 0, errors.New("tun device closed")
		}
	}
}

func (tun *NativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *NativeTun) Close() error {
	var err1 error
	if tun.statusListenersShutdown != nil {
		close(tun.statusListenersShutdown)
		if tun.netlinkCancel != nil {
			err1 = tun.netlinkCancel.Cancel()
		}
	} else if tun.events != nil {
		close(tun.events)
	}
	err2 := tun.fd.Close()
	err3 := tun.fdCancel.Cancel()

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func CreateTUN(name string) (TUNDevice, error) {

	// open clone device

	// HACK: we open it as a raw Fd first, so that f.nonblock=false
	// when we make it into a file object.
	nfd, err := unix.Open(cloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
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
		return nil, errors.New("interface name too long")
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

	return CreateTUNFromFile(fd)
}

func CreateTUNFromFile(fd *os.File) (TUNDevice, error) {
	tun := &NativeTun{
		fd:                      fd,
		events:                  make(chan TUNEvent, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
		nopi: false,
	}
	var err error

	tun.fdCancel, err = rwcancel.NewRWCancel(int(fd.Fd()))
	if err != nil {
		tun.fd.Close()
		return nil, err
	}

	_, err = tun.Name()
	if err != nil {
		tun.fd.Close()
		return nil, err
	}

	// start event listener

	tun.index, err = getIFIndex(tun.name)
	if err != nil {
		return nil, err
	}

	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		tun.fd.Close()
		return nil, err
	}
	tun.netlinkCancel, err = rwcancel.NewRWCancel(tun.netlinkSock)
	if err != nil {
		tun.fd.Close()
		return nil, err
	}

	tun.hackListenerClosed.Lock()
	go tun.RoutineNetlinkListener()
	go tun.RoutineHackListener() // cross namespace

	// set default MTU

	err = tun.setMTU(DefaultMTU)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}
