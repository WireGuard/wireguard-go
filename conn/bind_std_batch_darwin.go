//go:build darwin

package conn

import (
	"encoding/binary"
	"net"
	"os"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/darwinmsgx"
)

const stdNetBindBatches = true

type darwinBatchConn struct {
	conn        *net.UDPConn
	readmsghdrs [IdealBatchSize]darwinmsgx.MsghdrX
	readsas     [IdealBatchSize]unix.RawSockaddrAny
	readIovecs  [IdealBatchSize]unix.Iovec
}

// udpBatchEnabled is true unless WG_UDP_BATCH=0 (or "false").
// Used to A/B Darwin sendmsg_x/recvmsg_x against single-datagram UDP I/O
// while leaving utun batching unchanged.
func udpBatchEnabled() bool {
	switch os.Getenv("WG_UDP_BATCH") {
	case "0", "false", "off":
		return false
	default:
		return true
	}
}

func (s *StdNetBind) setupBatch(v4conn, v6conn *net.UDPConn) {
	if !udpBatchEnabled() {
		return
	}
	if v4conn != nil {
		s.batch4 = &darwinBatchConn{conn: v4conn}
	}
	if v6conn != nil {
		s.batch6 = &darwinBatchConn{conn: v6conn}
	}
}

func (c *darwinBatchConn) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	_ = flags

	for i := range msgs {
		buf := msgs[i].Buffers[0]
		if len(buf) == 0 {
			continue
		}
		c.readIovecs[i].Base = &buf[0]
		c.readIovecs[i].Len = uint64(len(buf))
		c.readmsghdrs[i] = darwinmsgx.MsghdrX{
			Msghdr: unix.Msghdr{
				Name:    (*byte)(unsafe.Pointer(&c.readsas[i])),
				Namelen: uint32(unix.SizeofSockaddrAny),
				Iov:     &c.readIovecs[i],
				Iovlen:  1,
			},
		}
	}

	rc, err := c.conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	n, err := darwinmsgx.RecvmsgX(rc, c.readmsghdrs[:len(msgs)])
	if err != nil {
		return n, err
	}
	for i := 0; i < n; i++ {
		msgs[i].N = int(c.readmsghdrs[i].DataLen)
		msgs[i].Addr = sockaddrAnyToUDPAddr(&c.readsas[i])
	}
	return n, nil
}

func (c *darwinBatchConn) WriteBatch(msgs []ipv6.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	_ = flags

	n := len(msgs)
	msghdrs := make([]darwinmsgx.MsghdrX, n)
	iovecs := make([]unix.Iovec, n)
	sa4s := make([]unix.RawSockaddrInet4, n)
	sa6s := make([]unix.RawSockaddrInet6, n)

	for i, msg := range msgs {
		addr := msg.Addr.(*net.UDPAddr)
		var name *byte
		var namelen uint32
		if ip4 := addr.IP.To4(); ip4 != nil {
			sa4s[i].Len = unix.SizeofSockaddrInet4
			sa4s[i].Family = unix.AF_INET
			p := (*[2]byte)(unsafe.Pointer(&sa4s[i].Port))
			p[0] = byte(addr.Port >> 8)
			p[1] = byte(addr.Port)
			copy(sa4s[i].Addr[:], ip4)
			name = (*byte)(unsafe.Pointer(&sa4s[i]))
			namelen = unix.SizeofSockaddrInet4
		} else {
			ip6 := addr.IP.To16()
			sa6s[i].Len = unix.SizeofSockaddrInet6
			sa6s[i].Family = unix.AF_INET6
			p := (*[2]byte)(unsafe.Pointer(&sa6s[i].Port))
			p[0] = byte(addr.Port >> 8)
			p[1] = byte(addr.Port)
			copy(sa6s[i].Addr[:], ip6)
			name = (*byte)(unsafe.Pointer(&sa6s[i]))
			namelen = unix.SizeofSockaddrInet6
			// TODO: handle IPv6 zone / Scope_id
		}

		buf := msg.Buffers[0]
		iovecs[i].Base = &buf[0]
		iovecs[i].Len = uint64(len(buf))
		msghdrs[i] = darwinmsgx.MsghdrX{
			Msghdr: unix.Msghdr{
				Name:    name,
				Namelen: namelen,
				Iov:     &iovecs[i],
				Iovlen:  1,
			},
		}
	}

	rc, err := c.conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	return darwinmsgx.SendmsgX(rc, msghdrs)
}

func sockaddrAnyToUDPAddr(sa *unix.RawSockaddrAny) *net.UDPAddr {
	switch sa.Addr.Family {
	case unix.AF_INET:
		rsa := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:]))
		ip := make(net.IP, net.IPv4len)
		copy(ip, rsa.Addr[:])
		return &net.UDPAddr{IP: ip, Port: port}
	case unix.AF_INET6:
		rsa := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:]))
		ip := make(net.IP, net.IPv6len)
		copy(ip, rsa.Addr[:])
		return &net.UDPAddr{IP: ip, Port: port}
	default:
		return nil
	}
}
