// +build !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 *
 * This implements userspace semantics of "sticky sockets", modeled after
 * WireGuard's kernelspace implementation. This is more or less a straight port
 * of the sticky-sockets.c example code:
 * https://git.zx2c4.com/WireGuard/tree/contrib/examples/sticky-sockets/sticky-sockets.c
 *
 * Currently there is no way to achieve this within the net package:
 * See e.g. https://github.com/golang/go/issues/17930
 * So this code is remains platform dependent.
 */

package device

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/rwcancel"
)

const (
	FD_ERR = -1
)

type IPv4Source struct {
	src     [4]byte
	ifindex int32
}

type IPv6Source struct {
	src [16]byte
	//ifindex belongs in dst.ZoneId
}

type NativeEndpoint struct {
	sync.Mutex
	dst  [unsafe.Sizeof(unix.SockaddrInet6{})]byte
	src  [unsafe.Sizeof(IPv6Source{})]byte
	isV6 bool
}

func (endpoint *NativeEndpoint) src4() *IPv4Source {
	return (*IPv4Source)(unsafe.Pointer(&endpoint.src[0]))
}

func (endpoint *NativeEndpoint) src6() *IPv6Source {
	return (*IPv6Source)(unsafe.Pointer(&endpoint.src[0]))
}

func (endpoint *NativeEndpoint) dst4() *unix.SockaddrInet4 {
	return (*unix.SockaddrInet4)(unsafe.Pointer(&endpoint.dst[0]))
}

func (endpoint *NativeEndpoint) dst6() *unix.SockaddrInet6 {
	return (*unix.SockaddrInet6)(unsafe.Pointer(&endpoint.dst[0]))
}

type nativeBind struct {
	sock4         int
	sock6         int
	netlinkSock   int
	netlinkCancel *rwcancel.RWCancel
	lastMark      uint32
}

var _ Endpoint = (*NativeEndpoint)(nil)
var _ Bind = (*nativeBind)(nil)

func CreateEndpoint(s string) (Endpoint, error) {
	var end NativeEndpoint
	addr, err := parseEndpoint(s)
	if err != nil {
		return nil, err
	}

	ipv4 := addr.IP.To4()
	if ipv4 != nil {
		dst := end.dst4()
		end.isV6 = false
		dst.Port = addr.Port
		copy(dst.Addr[:], ipv4)
		end.ClearSrc()
		return &end, nil
	}

	ipv6 := addr.IP.To16()
	if ipv6 != nil {
		zone, err := zoneToUint32(addr.Zone)
		if err != nil {
			return nil, err
		}
		dst := end.dst6()
		end.isV6 = true
		dst.Port = addr.Port
		dst.ZoneId = zone
		copy(dst.Addr[:], ipv6[:])
		end.ClearSrc()
		return &end, nil
	}

	return nil, errors.New("Invalid IP address")
}

func createNetlinkRouteSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: uint32(1 << (unix.RTNLGRP_IPV4_ROUTE - 1)),
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		unix.Close(sock)
		return -1, err
	}
	return sock, nil

}

func CreateBind(port uint16, device *Device) (*nativeBind, uint16, error) {
	var err error
	var bind nativeBind
	var newPort uint16

	bind.netlinkSock, err = createNetlinkRouteSocket()
	if err != nil {
		return nil, 0, err
	}
	bind.netlinkCancel, err = rwcancel.NewRWCancel(bind.netlinkSock)
	if err != nil {
		unix.Close(bind.netlinkSock)
		return nil, 0, err
	}

	go bind.routineRouteListener(device)

	// attempt ipv6 bind, update port if successful

	bind.sock6, newPort, err = create6(port)
	if err != nil {
		if err != syscall.EAFNOSUPPORT {
			bind.netlinkCancel.Cancel()
			return nil, 0, err
		}
	} else {
		port = newPort
	}

	// attempt ipv4 bind, update port if successful

	bind.sock4, newPort, err = create4(port)
	if err != nil {
		if err != syscall.EAFNOSUPPORT {
			bind.netlinkCancel.Cancel()
			unix.Close(bind.sock6)
			return nil, 0, err
		}
	} else {
		port = newPort
	}

	if bind.sock4 == FD_ERR && bind.sock6 == FD_ERR {
		return nil, 0, errors.New("ipv4 and ipv6 not supported")
	}

	return &bind, port, nil
}

func (bind *nativeBind) SetMark(value uint32) error {
	if bind.sock6 != -1 {
		err := unix.SetsockoptInt(
			bind.sock6,
			unix.SOL_SOCKET,
			unix.SO_MARK,
			int(value),
		)

		if err != nil {
			return err
		}
	}

	if bind.sock4 != -1 {
		err := unix.SetsockoptInt(
			bind.sock4,
			unix.SOL_SOCKET,
			unix.SO_MARK,
			int(value),
		)

		if err != nil {
			return err
		}
	}

	bind.lastMark = value
	return nil
}

func closeUnblock(fd int) error {
	// shutdown to unblock readers and writers
	unix.Shutdown(fd, unix.SHUT_RDWR)
	return unix.Close(fd)
}

func (bind *nativeBind) Close() error {
	var err1, err2, err3 error
	if bind.sock6 != -1 {
		err1 = closeUnblock(bind.sock6)
	}
	if bind.sock4 != -1 {
		err2 = closeUnblock(bind.sock4)
	}
	err3 = bind.netlinkCancel.Cancel()

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (bind *nativeBind) ReceiveIPv6(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	if bind.sock6 == -1 {
		return 0, nil, syscall.EAFNOSUPPORT
	}
	n, err := receive6(
		bind.sock6,
		buff,
		&end,
	)
	return n, &end, err
}

func (bind *nativeBind) ReceiveIPv4(buff []byte) (int, Endpoint, error) {
	var end NativeEndpoint
	if bind.sock4 == -1 {
		return 0, nil, syscall.EAFNOSUPPORT
	}
	n, err := receive4(
		bind.sock4,
		buff,
		&end,
	)
	return n, &end, err
}

func (bind *nativeBind) Send(buff []byte, end Endpoint) error {
	nend := end.(*NativeEndpoint)
	if !nend.isV6 {
		if bind.sock4 == -1 {
			return syscall.EAFNOSUPPORT
		}
		return send4(bind.sock4, nend, buff)
	} else {
		if bind.sock6 == -1 {
			return syscall.EAFNOSUPPORT
		}
		return send6(bind.sock6, nend, buff)
	}
}

func (end *NativeEndpoint) SrcIP() net.IP {
	if !end.isV6 {
		return net.IPv4(
			end.src4().src[0],
			end.src4().src[1],
			end.src4().src[2],
			end.src4().src[3],
		)
	} else {
		return end.src6().src[:]
	}
}

func (end *NativeEndpoint) DstIP() net.IP {
	if !end.isV6 {
		return net.IPv4(
			end.dst4().Addr[0],
			end.dst4().Addr[1],
			end.dst4().Addr[2],
			end.dst4().Addr[3],
		)
	} else {
		return end.dst6().Addr[:]
	}
}

func (end *NativeEndpoint) DstToBytes() []byte {
	if !end.isV6 {
		return (*[unsafe.Offsetof(end.dst4().Addr) + unsafe.Sizeof(end.dst4().Addr)]byte)(unsafe.Pointer(end.dst4()))[:]
	} else {
		return (*[unsafe.Offsetof(end.dst6().Addr) + unsafe.Sizeof(end.dst6().Addr)]byte)(unsafe.Pointer(end.dst6()))[:]
	}
}

func (end *NativeEndpoint) SrcToString() string {
	return end.SrcIP().String()
}

func (end *NativeEndpoint) DstToString() string {
	var udpAddr net.UDPAddr
	udpAddr.IP = end.DstIP()
	if !end.isV6 {
		udpAddr.Port = end.dst4().Port
	} else {
		udpAddr.Port = end.dst6().Port
	}
	return udpAddr.String()
}

func (end *NativeEndpoint) ClearDst() {
	for i := range end.dst {
		end.dst[i] = 0
	}
}

func (end *NativeEndpoint) ClearSrc() {
	for i := range end.src {
		end.src[i] = 0
	}
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
		return FD_ERR, 0, err
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
		return FD_ERR, 0, err
	}

	sa, err := unix.Getsockname(fd)
	if err == nil {
		addr.Port = sa.(*unix.SockaddrInet4).Port
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
		return FD_ERR, 0, err
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
		return FD_ERR, 0, err
	}

	sa, err := unix.Getsockname(fd)
	if err == nil {
		addr.Port = sa.(*unix.SockaddrInet6).Port
	}

	return fd, uint16(addr.Port), err
}

func send4(sock int, end *NativeEndpoint, buff []byte) error {

	// construct message header

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
			Spec_dst: end.src4().src,
			Ifindex:  end.src4().ifindex,
		},
	}

	end.Lock()
	_, err := unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst4(), 0)
	end.Unlock()

	if err == nil {
		return nil
	}

	// clear src and retry

	if err == unix.EINVAL {
		end.ClearSrc()
		cmsg.pktinfo = unix.Inet4Pktinfo{}
		end.Lock()
		_, err = unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst4(), 0)
		end.Unlock()
	}

	return err
}

func send6(sock int, end *NativeEndpoint, buff []byte) error {

	// construct message header

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
			Addr:    end.src6().src,
			Ifindex: end.dst6().ZoneId,
		},
	}

	if cmsg.pktinfo.Addr == [16]byte{} {
		cmsg.pktinfo.Ifindex = 0
	}

	end.Lock()
	_, err := unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst6(), 0)
	end.Unlock()

	if err == nil {
		return nil
	}

	// clear src and retry

	if err == unix.EINVAL {
		end.ClearSrc()
		cmsg.pktinfo = unix.Inet6Pktinfo{}
		end.Lock()
		_, err = unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst6(), 0)
		end.Unlock()
	}

	return err
}

func receive4(sock int, buff []byte, end *NativeEndpoint) (int, error) {

	// construct message header

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet4Pktinfo
	}

	size, _, _, newDst, err := unix.Recvmsg(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], 0)

	if err != nil {
		return 0, err
	}
	end.isV6 = false

	if newDst4, ok := newDst.(*unix.SockaddrInet4); ok {
		*end.dst4() = *newDst4
	}

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IP &&
		cmsg.cmsghdr.Type == unix.IP_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet4Pktinfo {
		end.src4().src = cmsg.pktinfo.Spec_dst
		end.src4().ifindex = cmsg.pktinfo.Ifindex
	}

	return size, nil
}

func receive6(sock int, buff []byte, end *NativeEndpoint) (int, error) {

	// construct message header

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet6Pktinfo
	}

	size, _, _, newDst, err := unix.Recvmsg(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], 0)

	if err != nil {
		return 0, err
	}
	end.isV6 = true

	if newDst6, ok := newDst.(*unix.SockaddrInet6); ok {
		*end.dst6() = *newDst6
	}

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 &&
		cmsg.cmsghdr.Type == unix.IPV6_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet6Pktinfo {
		end.src6().src = cmsg.pktinfo.Addr
		end.dst6().ZoneId = cmsg.pktinfo.Ifindex
	}

	return size, nil
}

func (bind *nativeBind) routineRouteListener(device *Device) {
	type peerEndpointPtr struct {
		peer     *Peer
		endpoint *Endpoint
	}
	var reqPeer map[uint32]peerEndpointPtr
	var reqPeerLock sync.Mutex

	defer unix.Close(bind.netlinkSock)

	for msg := make([]byte, 1<<16); ; {
		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(bind.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !bind.netlinkCancel.ReadyRead() {
				return
			}
		}
		if err != nil {
			return
		}

		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if uint(hdr.Len) > uint(len(remain)) {
				break
			}

			switch hdr.Type {
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
				if hdr.Seq <= MaxPeers && hdr.Seq > 0 {
					if uint(len(remain)) < uint(hdr.Len) {
						break
					}
					if hdr.Len > unix.SizeofNlMsghdr+unix.SizeofRtMsg {
						attr := remain[unix.SizeofNlMsghdr+unix.SizeofRtMsg:]
						for {
							if uint(len(attr)) < uint(unix.SizeofRtAttr) {
								break
							}
							attrhdr := *(*unix.RtAttr)(unsafe.Pointer(&attr[0]))
							if attrhdr.Len < unix.SizeofRtAttr || uint(len(attr)) < uint(attrhdr.Len) {
								break
							}
							if attrhdr.Type == unix.RTA_OIF && attrhdr.Len == unix.SizeofRtAttr+4 {
								ifidx := *(*uint32)(unsafe.Pointer(&attr[unix.SizeofRtAttr]))
								reqPeerLock.Lock()
								if reqPeer == nil {
									reqPeerLock.Unlock()
									break
								}
								pePtr, ok := reqPeer[hdr.Seq]
								reqPeerLock.Unlock()
								if !ok {
									break
								}
								pePtr.peer.Lock()
								if &pePtr.peer.endpoint != pePtr.endpoint {
									pePtr.peer.Unlock()
									break
								}
								if uint32(pePtr.peer.endpoint.(*NativeEndpoint).src4().ifindex) == ifidx {
									pePtr.peer.Unlock()
									break
								}
								pePtr.peer.endpoint.(*NativeEndpoint).ClearSrc()
								pePtr.peer.Unlock()
							}
							attr = attr[attrhdr.Len:]
						}
					}
					break
				}
				reqPeerLock.Lock()
				reqPeer = make(map[uint32]peerEndpointPtr)
				reqPeerLock.Unlock()
				go func() {
					device.peers.RLock()
					i := uint32(1)
					for _, peer := range device.peers.keyMap {
						peer.RLock()
						if peer.endpoint == nil || peer.endpoint.(*NativeEndpoint) == nil {
							peer.RUnlock()
							continue
						}
						if peer.endpoint.(*NativeEndpoint).isV6 || peer.endpoint.(*NativeEndpoint).src4().ifindex == 0 {
							peer.RUnlock()
							break
						}
						nlmsg := struct {
							hdr     unix.NlMsghdr
							msg     unix.RtMsg
							dsthdr  unix.RtAttr
							dst     [4]byte
							srchdr  unix.RtAttr
							src     [4]byte
							markhdr unix.RtAttr
							mark    uint32
						}{
							unix.NlMsghdr{
								Type:  uint16(unix.RTM_GETROUTE),
								Flags: unix.NLM_F_REQUEST,
								Seq:   i,
							},
							unix.RtMsg{
								Family:  unix.AF_INET,
								Dst_len: 32,
								Src_len: 32,
							},
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_DST,
							},
							peer.endpoint.(*NativeEndpoint).dst4().Addr,
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_SRC,
							},
							peer.endpoint.(*NativeEndpoint).src4().src,
							unix.RtAttr{
								Len:  8,
								Type: unix.RTA_MARK,
							},
							uint32(bind.lastMark),
						}
						nlmsg.hdr.Len = uint32(unsafe.Sizeof(nlmsg))
						reqPeerLock.Lock()
						reqPeer[i] = peerEndpointPtr{
							peer:     peer,
							endpoint: &peer.endpoint,
						}
						reqPeerLock.Unlock()
						peer.RUnlock()
						i++
						_, err := bind.netlinkCancel.Write((*[unsafe.Sizeof(nlmsg)]byte)(unsafe.Pointer(&nlmsg))[:])
						if err != nil {
							break
						}
					}
					device.peers.RUnlock()
				}()
			}
			remain = remain[hdr.Len:]
		}
	}
}
