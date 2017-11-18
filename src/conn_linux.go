/* Copyright 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This implements userspace semantics of "sticky sockets", modeled after
 * WireGuard's kernelspace implementation.
 */

package main

import (
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"unsafe"
)

/* Supports source address caching
 *
 * Currently there is no way to achieve this within the net package:
 * See e.g. https://github.com/golang/go/issues/17930
 * So this code is remains platform dependent.
 */
type NativeEndpoint struct {
	src unix.RawSockaddrInet6
	dst unix.RawSockaddrInet6
}

type NativeBind struct {
	sock4 int
	sock6 int
}

var _ Endpoint = (*NativeEndpoint)(nil)
var _ Bind = NativeBind{}

type IPv4Source struct {
	src     unix.RawSockaddrInet4
	Ifindex int32
}

func htons(val uint16) uint16 {
	var out [unsafe.Sizeof(val)]byte
	binary.BigEndian.PutUint16(out[:], val)
	return *((*uint16)(unsafe.Pointer(&out[0])))
}

func ntohs(val uint16) uint16 {
	tmp := ((*[unsafe.Sizeof(val)]byte)(unsafe.Pointer(&val)))
	return binary.BigEndian.Uint16((*tmp)[:])
}

func NewEndpoint() Endpoint {
	return &NativeEndpoint{}
}

func CreateUDPBind(port uint16) (Bind, uint16, error) {
	var err error
	var bind NativeBind

	bind.sock6, port, err = create6(port)
	if err != nil {
		return nil, port, err
	}

	bind.sock4, port, err = create4(port)
	if err != nil {
		unix.Close(bind.sock6)
	}
	return bind, port, err
}

func (bind NativeBind) SetMark(value uint32) error {
	err := unix.SetsockoptInt(
		bind.sock6,
		unix.SOL_SOCKET,
		unix.SO_MARK,
		int(value),
	)

	if err != nil {
		return err
	}

	return unix.SetsockoptInt(
		bind.sock4,
		unix.SOL_SOCKET,
		unix.SO_MARK,
		int(value),
	)
}

func closeUnblock(fd int) error {
	// shutdown to unblock readers
	unix.Shutdown(fd, unix.SHUT_RD)
	return unix.Close(fd)
}

func (bind NativeBind) Close() error {
	err1 := closeUnblock(bind.sock6)
	err2 := closeUnblock(bind.sock4)
	if err1 != nil {
		return err1
	}
	return err2
}

func (bind NativeBind) ReceiveIPv6(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	n, err := receive6(
		bind.sock6,
		buff,
		&end,
	)
	return n, &end, err
}

func (bind NativeBind) ReceiveIPv4(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	n, err := receive4(
		bind.sock4,
		buff,
		&end,
	)
	return n, &end, err
}

func (bind NativeBind) Send(buff []byte, end Endpoint) error {
	nend := end.(*NativeEndpoint)
	switch nend.dst.Family {
	case unix.AF_INET6:
		return send6(bind.sock6, nend, buff)
	case unix.AF_INET:
		return send4(bind.sock4, nend, buff)
	default:
		return errors.New("Unknown address family of destination")
	}
}

func sockaddrToString(addr unix.RawSockaddrInet6) string {
	var udpAddr net.UDPAddr

	switch addr.Family {
	case unix.AF_INET6:
		udpAddr.Port = int(ntohs(addr.Port))
		udpAddr.IP = addr.Addr[:]
		return udpAddr.String()

	case unix.AF_INET:
		ptr := (*unix.RawSockaddrInet4)(unsafe.Pointer(&addr))
		udpAddr.Port = int(ntohs(ptr.Port))
		udpAddr.IP = net.IPv4(
			ptr.Addr[0],
			ptr.Addr[1],
			ptr.Addr[2],
			ptr.Addr[3],
		)
		return udpAddr.String()

	default:
		return "<unknown address family>"
	}
}

func rawAddrToIP(addr unix.RawSockaddrInet6) net.IP {
	switch addr.Family {
	case unix.AF_INET6:
		return addr.Addr[:]
	case unix.AF_INET:
		ptr := (*unix.RawSockaddrInet4)(unsafe.Pointer(&addr))
		return net.IPv4(
			ptr.Addr[0],
			ptr.Addr[1],
			ptr.Addr[2],
			ptr.Addr[3],
		)
	default:
		return nil
	}
}

func (end *NativeEndpoint) SrcIP() net.IP {
	return rawAddrToIP(end.src)
}

func (end *NativeEndpoint) DstIP() net.IP {
	return rawAddrToIP(end.dst)
}

func (end *NativeEndpoint) DstToBytes() []byte {
	ptr := unsafe.Pointer(&end.src)
	arr := (*[unix.SizeofSockaddrInet6]byte)(ptr)
	return arr[:]
}

func (end *NativeEndpoint) SrcToString() string {
	return sockaddrToString(end.src)
}

func (end *NativeEndpoint) DstToString() string {
	return sockaddrToString(end.dst)
}

func (end *NativeEndpoint) ClearDst() {
	end.dst = unix.RawSockaddrInet6{}
}

func (end *NativeEndpoint) ClearSrc() {
	end.src = unix.RawSockaddrInet6{}
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

func create4(port uint16) (int, uint16, error) {

	// create socket

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return -1, 0, err
	}

	addr := unix.SockaddrInet4{
		Port: int(port),
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

		return unix.Bind(fd, &addr)
	}(); err != nil {
		unix.Close(fd)
	}

	return fd, uint16(addr.Port), err
}

func create6(port uint16) (int, uint16, error) {

	// create socket

	fd, err := unix.Socket(
		unix.AF_INET6,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return -1, 0, err
	}

	// set sockopts and bind

	addr := unix.SockaddrInet6{
		Port: int(port),
	}

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

		return unix.Bind(fd, &addr)

	}(); err != nil {
		unix.Close(fd)
	}

	return fd, uint16(addr.Port), err
}

func (end *NativeEndpoint) SetDst(s string) error {
	addr, err := parseEndpoint(s)
	if err != nil {
		return err
	}

	ipv4 := addr.IP.To4()
	if ipv4 != nil {
		dst := (*unix.RawSockaddrInet4)(unsafe.Pointer(&end.dst))
		dst.Family = unix.AF_INET
		dst.Port = htons(uint16(addr.Port))
		dst.Zero = [8]byte{}
		copy(dst.Addr[:], ipv4)
		end.ClearSrc()
		return nil
	}

	ipv6 := addr.IP.To16()
	if ipv6 != nil {
		zone, err := zoneToUint32(addr.Zone)
		if err != nil {
			return err
		}
		dst := &end.dst
		dst.Family = unix.AF_INET6
		dst.Port = htons(uint16(addr.Port))
		dst.Flowinfo = 0
		dst.Scope_id = zone
		copy(dst.Addr[:], ipv6[:])
		end.ClearSrc()
		return nil
	}

	return errors.New("Failed to recognize IP address format")
}

func send6(sock int, end *NativeEndpoint, buff []byte) error {

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
			Len:   unix.SizeofInet6Pktinfo + unix.SizeofCmsghdr,
		},
		unix.Inet6Pktinfo{
			Addr:    end.src.Addr,
			Ifindex: end.src.Scope_id,
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
		uintptr(sock),
		uintptr(unsafe.Pointer(&msghdr)),
		0,
	)

	if errno == 0 {
		return nil
	}

	// clear src and retry

	if errno == unix.EINVAL {
		end.ClearSrc()
		cmsg.pktinfo = unix.Inet6Pktinfo{}
		_, _, errno = unix.Syscall(
			unix.SYS_SENDMSG,
			uintptr(sock),
			uintptr(unsafe.Pointer(&msghdr)),
			0,
		)
	}

	return errno
}

func send4(sock int, end *NativeEndpoint, buff []byte) error {

	// construct message header

	var iovec unix.Iovec
	iovec.Base = (*byte)(unsafe.Pointer(&buff[0]))
	iovec.SetLen(len(buff))

	src4 := (*IPv4Source)(unsafe.Pointer(&end.src))

	cmsg := struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet4Pktinfo
	}{
		unix.Cmsghdr{
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_PKTINFO,
			Len:   unix.SizeofInet4Pktinfo + unix.SizeofCmsghdr,
		},
		unix.Inet4Pktinfo{
			Spec_dst: src4.src.Addr,
			Ifindex:  src4.Ifindex,
		},
	}

	msghdr := unix.Msghdr{
		Iov:     &iovec,
		Iovlen:  1,
		Name:    (*byte)(unsafe.Pointer(&end.dst)),
		Namelen: unix.SizeofSockaddrInet4,
		Control: (*byte)(unsafe.Pointer(&cmsg)),
		Flags:   0,
	}
	msghdr.SetControllen(int(unsafe.Sizeof(cmsg)))

	// sendmsg(sock, &msghdr, 0)

	_, _, errno := unix.Syscall(
		unix.SYS_SENDMSG,
		uintptr(sock),
		uintptr(unsafe.Pointer(&msghdr)),
		0,
	)

	// clear source and try again

	if errno == unix.EINVAL {
		end.ClearSrc()
		cmsg.pktinfo = unix.Inet4Pktinfo{}
		_, _, errno = unix.Syscall(
			unix.SYS_SENDMSG,
			uintptr(sock),
			uintptr(unsafe.Pointer(&msghdr)),
			0,
		)
	}

	// errno = 0 is still an error instance

	if errno == 0 {
		return nil
	}

	return errno
}

func receive4(sock int, buff []byte, end *NativeEndpoint) (int, error) {

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

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IP &&
		cmsg.cmsghdr.Type == unix.IP_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet4Pktinfo {
		src4 := (*IPv4Source)(unsafe.Pointer(&end.src))
		src4.src.Family = unix.AF_INET
		src4.src.Addr = cmsg.pktinfo.Spec_dst
		src4.Ifindex = cmsg.pktinfo.Ifindex
	}

	return int(size), nil
}

func receive6(sock int, buff []byte, end *NativeEndpoint) (int, error) {

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

	size, _, errno := unix.Syscall(
		unix.SYS_RECVMSG,
		uintptr(sock),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)

	if errno != 0 {
		return 0, errno
	}

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 &&
		cmsg.cmsghdr.Type == unix.IPV6_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet6Pktinfo {
		end.src.Family = unix.AF_INET6
		end.src.Addr = cmsg.pktinfo.Addr
		end.src.Scope_id = cmsg.pktinfo.Ifindex
	}

	return int(size), nil
}
