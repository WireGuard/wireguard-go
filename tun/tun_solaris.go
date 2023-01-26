/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ipNode  = "/dev/ip"
	tunNode = "/dev/tun"
)

type NativeTun struct {
	fd          int
	tunFile     *os.File
	events      chan Event
	errors      chan error
	ipfd        int
	routeSocket int
	name        string
	closeOnce   sync.Once
}

func (tun *NativeTun) routineRouteListener() {
	var (
		statusUp  bool
		statusMTU int
	)

	defer close(tun.events)

	iface, err := net.InterfaceByName(tun.name)
	if err != nil {
		tun.errors <- err
		return
	}
	tunIfindex := iface.Index

	routeSocket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.errors <- err
		return
	}
	defer unix.Close(routeSocket)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(routeSocket, data)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				goto retry
			}
			tun.errors <- err
			return
		}

		// You might expect to get a unix.RtMsghdr, but if the Type is RTM_IFINFO then
		// it's really supposed to be parsed as a IfMsghdr
		// See https://github.com/illumos/illumos-gate/blob/550b6e4/usr/src/cmd/cmd-inet/usr.sbin/route.c#L2614-L2620

		if uintptr(n) < unsafe.Sizeof(unix.IfMsghdr{}) {
			continue
		}
		msg := (*unix.IfMsghdr)(unsafe.Pointer(&data[0]))
		if int(msg.Type) != unix.RTM_IFINFO {
			continue
		}
		if int(msg.Index) != tunIfindex {
			continue
		}

		iface, err := net.InterfaceByName(tun.name)
		if err != nil {
			tun.errors <- err
			return
		}

		// Currently the solaris/illumos tun driver has two quirks that should be noted here
		// 1. At creation time it immediately goes up before this code will have
		// a chance to notice
		// 2. It doesn't really respect 'ifconfig tunN down' properly so this code
		// won't notice, and it will be broken and refuse to come back up
		// if it is set down.
		// If that ever changes, this code will be waiting.

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

func tunDestroy(name string) error {
	var l unix.Lifreq
	if err := l.SetName(name); err != nil {
		return err
	}
	// cleanup both ipv4 and ipv6
	for _, proto := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(proto, unix.SOCK_DGRAM, 0)
		if err != nil {
			return fmt.Errorf("could not open Socket of type %v", proto)
		}
		defer unix.Close(fd)

		// get the STREAMS muxid for the tun device stream
		reqnum := int(unix.SIOCGLIFMUXID)

		// solaris/illumos defines the ioctl number as a signed int, but the
		// common x/sys/unix functions use uint.
		if err := unix.IoctlLifreq(fd, uint(reqnum), &l); err != nil {
			continue
		}

		id := l.GetLifruInt()

		// Unlink the tun stream from the IP mutiplexor
		if err := unix.IoctlSetInt(fd, unix.I_PUNLINK, id); err != nil {
			continue
		}
	}
	return nil
}

func CreateTUN(name string, mtu int) (Device, error) {
	ppa := -1
	if name != "tun" {
		_, err := fmt.Sscanf(name, "tun%d", &ppa)
		if err != nil || ppa < 0 {
			return nil, fmt.Errorf("interface name must be tun[0-9]*")
		}
	}

	fd, err := unix.Open(tunNode, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open TUN (%s)", tunNode)
	}

	// The "tun" device is a STREAMS module.  We need to make a STREAMS ioctl
	// request to that module using the TUNNEWPPA command.  Returns the newly
	// allocated PPA number. Passing -1 will request a dynamically assinged
	// PPA. Passing a specific id will try to use the one specified.
	var s unix.Strioctl
	s.Cmd = unix.TUNNEWPPA
	s.SetInt(ppa)
	ppa, err = unix.IoctlSetStrioctlRetInt(fd, unix.I_STR, &s)
	if err != nil {
		return nil, err
	}

	assignedName := fmt.Sprintf("tun%d", ppa)

	// Clean up anything possibly left behind by a crash
	tunDestroy(assignedName)

	// The solaris/illumos tun driver doesn't have an ioctl for reading back the PPA.
	// Just pass it through to the daemon process via environment variable.
	err = os.Setenv("_WG_TUN_NAME", assignedName)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "")

	tun, err := CreateTUNFromFile(file, mtu)

	if err == nil && name == "tun" {
		fname := os.Getenv("WG_TUN_NAME_FILE")
		if fname != "" {
			os.WriteFile(fname, []byte(tun.(*NativeTun).name+"\n"), 0o400)
		}
	}

	return tun, err
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	// The solaris/illumos tun driver doesn't have an ioctl for reading back the PPA.
	// Just get it back via environment variable.
	name := os.Getenv("_WG_TUN_NAME")
	if name == "" {
		return nil, fmt.Errorf("could not determine device name")
	}

	// By holding open this file descriptor on /dev/ip for the life of the connection
	// and using I_LINK, STREAMS will tear everything down cleanly when we close these
	// file descriptors
	ipfd, err := unix.Open(ipNode, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", ipNode)
	}

	routeSocket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}

	tun := &NativeTun{
		fd:          int(file.Fd()),
		ipfd:        ipfd,
		name:        name,
		tunFile:     file,
		routeSocket: routeSocket,
		events:      make(chan Event, 10),
		errors:      make(chan error, 1),
	}

	err = tun.configureSTREAMS()
	if err != nil {
		tun.Close()
		return nil, err
	}

	go tun.routineRouteListener()

	err = tun.setMTU(mtu)
	if err != nil {
		tun.Close()
		return nil, err
	}

	// The interface up message was emitted before the listener was started
	// when the tun device was created. Emit the event here to compensate.
	tun.events <- EventUp

	// Always send an MTUUpdate event to ensure correct detection at startup
	tun.events <- EventMTUUpdate

	return tun, nil
}

func (tun *NativeTun) configureSTREAMS() error {
	// get back the ppa number from the name
	var ppa int
	_, err := fmt.Sscanf(tun.name, "tun%d", &ppa)
	if err != nil {
		return fmt.Errorf("received a bogus tun name: %s", tun.name)
	}

	// Unclear why, but we need to open a second handle on the tun device for
	// the ioctls that follow. Reusing the existing one does not work.
	tunFD, err := unix.Open(tunNode, unix.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("could not open TUN (%s)", tunNode)
	}
	defer unix.Close(tunFD)

	// Push the IP module onto the TUN device.
	if err = unix.IoctlSetString(tunFD, unix.I_PUSH, "ip"); err != nil {
		return fmt.Errorf("unable to push IP module: %v", err)
	}

	// select which ppa we're using
	req := int(unix.IF_UNITSEL)
	err = unix.IoctlSetPointerInt(tunFD, uint(req), ppa)
	if err != nil {
		return fmt.Errorf("unable to IF_UNITSEL: %v", err)
	}

	// link the tun stream to the IP multiplexor
	// If we used I_PLINK the connection would persist after we close the ipfd
	// which causes cleanup issues. By using I_LINK and holding ipfd open,
	// everything gets cleaned up nicely when we close the file descriptors
	// or when the process terminates.
	muxid, err := unix.IoctlSetIntRetInt(tun.ipfd, unix.I_LINK, tunFD)
	if err != nil {
		return fmt.Errorf("unable to I_LINK: %v", err)
	}

	var l unix.Lifreq
	if err := l.SetName(tun.name); err != nil {
		return fmt.Errorf("failed to set name on Lifreq :%v", err)
	}

	// set the IP muxid
	reqnum := int(unix.SIOCSLIFMUXID)
	l.SetLifruInt(muxid)
	if err = unix.IoctlLifreq(tun.ipfd, uint(reqnum), &l); err != nil {
		return fmt.Errorf("unable to SIOCSLIFMUXID: %v", err)
	}

	return nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		_, read, _, err := unix.Getmsg(tun.fd, nil, buffs[0][offset:])
		if err != nil {
			return 0, err
		}
		sizes[0] = len(read)
		return 1, nil
	}
}

func (tun *NativeTun) Write(buffs [][]byte, offset int) (int, error) {
	for i, buf := range buffs {
		buf = buf[offset:]
		if err := unix.Putmsg(tun.fd, nil, buf, 0); err != nil {
			return i, err
		}
	}
	return len(buffs), nil
}

func (tun *NativeTun) Close() error {
	var err1, err2, err3 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		err2 = unix.Close(tun.ipfd)
		if tun.routeSocket != -1 {
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err3 = unix.Close(tun.routeSocket)
			tun.routeSocket = -1
		} else if tun.events != nil {
			close(tun.events)
		}
	})
	// Clean up anything remaining
	// e.g. ipv6 addresses that were configured onto the device
	tunDestroy(tun.name)
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (tun *NativeTun) setMTU(n int) error {
	var l unix.Lifreq
	if err := l.SetName(tun.name); err != nil {
		return err
	}

	reqnum := int(unix.SIOCSLIFMTU)
	l.SetLifruUint(uint(n))
	if err := unix.IoctlLifreq(tun.ipfd, uint(reqnum), &l); err != nil {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.name, err)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	var l unix.Lifreq
	if err := l.SetName(tun.name); err != nil {
		return 0, err
	}

	reqnum := int(unix.SIOCGLIFMTU)
	if err := unix.IoctlLifreq(tun.ipfd, uint(reqnum), &l); err != nil {
		return 0, fmt.Errorf("unable to SIOCGLIFMTU: %v", err)
	}
	return int(l.GetLifruUint()), nil
}

func (tun *NativeTun) BatchSize() (int) {
	return 1
}
