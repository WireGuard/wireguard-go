/* Copyright 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This implements userspace semantics of "sticky sockets", modeled after
 * WireGuard's kernelspace implementation.
 */

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"unsafe"
)

/* Supports source address caching
 *
 * It is important that the endpoint is only updated after the packet content has been authenticated.
 *
 * Currently there is no way to achieve this within the net package:
 * See e.g. https://github.com/golang/go/issues/17930
 */
type Endpoint struct {
	// source (selected based on dst type)
	// (could use RawSockaddrAny and unsafe)
	srcIPv6 unix.RawSockaddrInet6
	srcIPv4 unix.RawSockaddrInet4
	srcIf4  int32

	dst unix.RawSockaddrAny
}

func zoneToUint32(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if intr, err := net.InterfaceByName(zone); err == nil {
		return uint32(intr.Index), nil
	}
	n, err := strconv.ParseUint(zone, 10, 32)
	return uint32(n), err
}

func (end *Endpoint) ClearSrc() {
	end.srcIf4 = 0
	end.srcIPv4 = unix.RawSockaddrInet4{}
	end.srcIPv6 = unix.RawSockaddrInet6{}
}

func (end *Endpoint) Set(s string) error {
	addr, err := parseEndpoint(s)
	if err != nil {
		return err
	}

	ipv6 := addr.IP.To16()
	if ipv6 != nil {
		zone, err := zoneToUint32(addr.Zone)
		if err != nil {
			return err
		}
		ptr := (*unix.RawSockaddrInet6)(unsafe.Pointer(&end.dst))
		ptr.Family = unix.AF_INET6
		ptr.Port = uint16(addr.Port)
		ptr.Flowinfo = 0
		ptr.Scope_id = zone
		copy(ptr.Addr[:], ipv6[:])
		end.ClearSrc()
		return nil
	}

	ipv4 := addr.IP.To4()
	if ipv4 != nil {
		ptr := (*unix.RawSockaddrInet4)(unsafe.Pointer(&end.dst))
		ptr.Family = unix.AF_INET
		ptr.Port = uint16(addr.Port)
		ptr.Zero = [8]byte{}
		copy(ptr.Addr[:], ipv4)
		end.ClearSrc()
		return nil
	}

	return errors.New("Failed to recognize IP address format")
}

func send6(sock uintptr, end *Endpoint, buff []byte) error {
	var iovec unix.Iovec

	iovec.Base = (*byte)(unsafe.Pointer(&buff[0]))
	iovec.SetLen(len(buff))

	cmsg := struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet6Pktinfo
	}{
		unix.Cmsghdr{
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
			Len:   unix.SizeofInet6Pktinfo,
		},
		unix.Inet6Pktinfo{
			Addr:    end.srcIPv6.Addr,
			Ifindex: end.srcIPv6.Scope_id,
		},
	}

	msghdr := unix.Msghdr{
		Iov:     &iovec,
		Iovlen:  1,
		Name:    (*byte)(unsafe.Pointer(&end.dst)),
		Namelen: unix.SizeofSockaddrInet6,
		Control: (*byte)(unsafe.Pointer(&cmsg)),
	}

	msghdr.SetControllen(int(unsafe.Sizeof(cmsg)))

	// sendmsg(sock, &msghdr, 0)

	_, _, errno := unix.Syscall(
		unix.SYS_SENDMSG,
		sock,
		uintptr(unsafe.Pointer(&msghdr)),
		0,
	)
	if errno == unix.EINVAL {
		end.ClearSrc()
	}
	return errno
}

func send4(sock uintptr, end *Endpoint, buff []byte) error {
	var iovec unix.Iovec

	iovec.Base = (*byte)(unsafe.Pointer(&buff[0]))
	iovec.SetLen(len(buff))

	cmsg := struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet4Pktinfo
	}{
		unix.Cmsghdr{
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_PKTINFO,
			Len:   unix.SizeofInet6Pktinfo,
		},
		unix.Inet4Pktinfo{
			Spec_dst: end.srcIPv4.Addr,
			Ifindex:  end.srcIf4,
		},
	}

	msghdr := unix.Msghdr{
		Iov:     &iovec,
		Iovlen:  1,
		Name:    (*byte)(unsafe.Pointer(&end.dst)),
		Namelen: unix.SizeofSockaddrInet4,
		Control: (*byte)(unsafe.Pointer(&cmsg)),
	}

	msghdr.SetControllen(int(unsafe.Sizeof(cmsg)))

	// sendmsg(sock, &msghdr, 0)

	_, _, errno := unix.Syscall(
		unix.SYS_SENDMSG,
		sock,
		uintptr(unsafe.Pointer(&msghdr)),
		0,
	)
	if errno == unix.EINVAL {
		end.ClearSrc()
	}
	return errno
}

func send(c *net.UDPConn, end *Endpoint, buff []byte) error {

	// extract underlying file descriptor

	file, err := c.File()
	if err != nil {
		return err
	}
	sock := file.Fd()

	// send depending on address family of dst

	family := *((*uint16)(unsafe.Pointer(&end.dst)))
	if family == unix.AF_INET {
		return send4(sock, end, buff)
	} else if family == unix.AF_INET6 {
		return send6(sock, end, buff)
	}
	return errors.New("Unknown address family of source")
}

func receiveIPv4(end *Endpoint, c *net.UDPConn, buff []byte) (error, *net.UDPAddr, *net.UDPAddr) {

	file, err := c.File()
	if err != nil {
		return err, nil, nil
	}

	var iovec unix.Iovec
	iovec.Base = (*byte)(unsafe.Pointer(&buff[0]))
	iovec.SetLen(len(buff))

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet6Pktinfo // big enough
	}

	var msg unix.Msghdr
	msg.Iov = &iovec
	msg.Iovlen = 1
	msg.Name = (*byte)(unsafe.Pointer(&end.dst))
	msg.Namelen = uint32(unix.SizeofSockaddrAny)
	msg.Control = (*byte)(unsafe.Pointer(&cmsg))
	msg.SetControllen(int(unsafe.Sizeof(cmsg)))

	_, _, errno := unix.Syscall(
		unix.SYS_RECVMSG,
		file.Fd(),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)

	if errno != 0 {
		return errno, nil, nil
	}

	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 &&
		cmsg.cmsghdr.Type == unix.IPV6_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet6Pktinfo {

	}

	if cmsg.cmsghdr.Level == unix.IPPROTO_IP &&
		cmsg.cmsghdr.Type == unix.IP_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet4Pktinfo {

		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&cmsg.pktinfo))
		println(info)

	}

	return nil, nil, nil
}

func setMark(conn *net.UDPConn, value uint32) error {
	if conn == nil {
		return nil
	}

	file, err := conn.File()
	if err != nil {
		return err
	}

	return unix.SetsockoptInt(
		int(file.Fd()),
		unix.SOL_SOCKET,
		unix.SO_MARK,
		int(value),
	)
}
