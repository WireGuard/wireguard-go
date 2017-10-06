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

import "fmt"

/* Supports source address caching
 *
 * Currently there is no way to achieve this within the net package:
 * See e.g. https://github.com/golang/go/issues/17930
 * So this code is platform dependent.
 *
 * It is important that the endpoint is only updated after the packet content has been authenticated!
 */

type Endpoint struct {
	// source (selected based on dst type)
	// (could use RawSockaddrAny and unsafe)
	src6   unix.RawSockaddrInet6
	src4   unix.RawSockaddrInet4
	src4if int32

	dst unix.RawSockaddrAny
}

type IPv4Socket int
type IPv6Socket int

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

func CreateIPv4Socket(port int) (IPv4Socket, error) {

	// create socket

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return -1, err
	}

	// set sockopts and bind

	if err := func() error {

		if err := unix.SetsockoptInt(
			fd,
			unix.SOL_SOCKET,
			unix.SO_REUSEADDR,
			1,
		); err != nil {
			return err
		}

		if err := unix.SetsockoptInt(
			fd,
			unix.IPPROTO_IP,
			unix.IP_PKTINFO,
			1,
		); err != nil {
			return err
		}

		addr := unix.SockaddrInet4{
			Port: port,
		}
		return unix.Bind(fd, &addr)

	}(); err != nil {
		unix.Close(fd)
	}

	return IPv4Socket(fd), err
}

func CreateIPv6Socket(port int) (IPv6Socket, error) {

	// create socket

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return -1, err
	}

	// set sockopts and bind

	if err := func() error {

		if err := unix.SetsockoptInt(
			fd,
			unix.SOL_SOCKET,
			unix.SO_REUSEADDR,
			1,
		); err != nil {
			return err
		}

		if err := unix.SetsockoptInt(
			fd,
			unix.IPPROTO_IPV6,
			unix.IPV6_RECVPKTINFO,
			1,
		); err != nil {
			return err
		}

		if err := unix.SetsockoptInt(
			fd,
			unix.IPPROTO_IPV6,
			unix.IPV6_V6ONLY,
			1,
		); err != nil {
			return err
		}

		addr := unix.SockaddrInet6{
			Port: port,
		}
		return unix.Bind(fd, &addr)

	}(); err != nil {
		unix.Close(fd)
	}

	return IPv6Socket(fd), err
}

func (end *Endpoint) ClearSrc() {
	end.src4if = 0
	end.src4 = unix.RawSockaddrInet4{}
	end.src6 = unix.RawSockaddrInet6{}
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

	// construct message header

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
			Addr:    end.src6.Addr,
			Ifindex: end.src6.Scope_id,
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

	// construct message header

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
			Len:   unix.SizeofInet4Pktinfo,
		},
		unix.Inet4Pktinfo{
			Spec_dst: end.src4.Addr,
			Ifindex:  end.src4if,
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

func (end *Endpoint) Send(c *net.UDPConn, buff []byte) error {

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

func (end *Endpoint) ReceiveIPv4(sock IPv4Socket, buff []byte) (int, error) {

	// contruct message header

	var iovec unix.Iovec
	iovec.Base = (*byte)(unsafe.Pointer(&buff[0]))
	iovec.SetLen(len(buff))

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet4Pktinfo
	}

	var msghdr unix.Msghdr
	msghdr.Iov = &iovec
	msghdr.Iovlen = 1
	msghdr.Name = (*byte)(unsafe.Pointer(&end.dst))
	msghdr.Namelen = unix.SizeofSockaddrInet4
	msghdr.Control = (*byte)(unsafe.Pointer(&cmsg))
	msghdr.SetControllen(int(unsafe.Sizeof(cmsg)))

	// recvmsg(sock, &mskhdr, 0)

	size, _, errno := unix.Syscall(
		unix.SYS_RECVMSG,
		uintptr(sock),
		uintptr(unsafe.Pointer(&msghdr)),
		0,
	)

	if errno != 0 {
		return 0, errno
	}

	fmt.Println(msghdr)
	fmt.Println(cmsg)

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IP &&
		cmsg.cmsghdr.Type == unix.IP_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet4Pktinfo {
		end.src4.Addr = cmsg.pktinfo.Spec_dst
		end.src4if = cmsg.pktinfo.Ifindex
	}

	return int(size), nil
}

func (end *Endpoint) ReceiveIPv6(sock IPv6Socket, buff []byte) error {

	// contruct message header

	var iovec unix.Iovec
	iovec.Base = (*byte)(unsafe.Pointer(&buff[0]))
	iovec.SetLen(len(buff))

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet6Pktinfo
	}

	var msg unix.Msghdr
	msg.Iov = &iovec
	msg.Iovlen = 1
	msg.Name = (*byte)(unsafe.Pointer(&end.dst))
	msg.Namelen = uint32(unix.SizeofSockaddrInet6)
	msg.Control = (*byte)(unsafe.Pointer(&cmsg))
	msg.SetControllen(int(unsafe.Sizeof(cmsg)))

	// recvmsg(sock, &mskhdr, 0)

	_, _, errno := unix.Syscall(
		unix.SYS_RECVMSG,
		uintptr(sock),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)

	if errno != 0 {
		return errno
	}

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 &&
		cmsg.cmsghdr.Type == unix.IPV6_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet6Pktinfo {
		end.src6.Addr = cmsg.pktinfo.Addr
		end.src6.Scope_id = cmsg.pktinfo.Ifindex
	}

	return nil
}

func SetMark(conn *net.UDPConn, value uint32) error {
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
