/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xnet"
	"golang.zx2c4.com/wireguard/tun"
)

// Net2 is a lneto-backed userspace network stack that implements both
// [tun.Device] (for WireGuard integration) and a networking API (Dial/Listen/DNS).
//
// Packet flow:
//   - Ingress (WireGuard → stack): [Net2.Write] calls [xnet.StackAsync.IngressIP].
//   - Egress  (stack → WireGuard): [Net2.egressLoop] polls [xnet.StackAsync.EgressIP]
//     and delivers ready frames to pktOut; [Net2.Read] blocks on pktOut.
//
// Lifecycle: created by [CreateNetTUN2], torn down by [Net2.Close] which closes
// done (signals egressLoop), events, and pktOut.
type Net2 struct {
	sa  xnet.StackAsync
	blk xnet.StackRetrying // wraps sa; created once in CreateNetTUN2
	sgo xnet.StackGo       // wraps sa; created once in CreateNetTUN2

	// events carries TUN state changes (e.g. EventUp) consumed by WireGuard's device loop.
	events chan tun.Event
	// pktOut carries egress IP frames from egressLoop to Read. Buffered to absorb
	// short bursts without stalling egressLoop on a slow WireGuard consumer.
	pktOut chan []byte
	// done is closed by Close to stop egressLoop and unblock any pending Read.
	done chan struct{}

	mtu        int
	dnsServers []netip.Addr
}

type TCPConn interface {
	Close() error
	CloseRead() error
	CloseWrite() error
	LocalAddr() net.Addr
	Read(b []byte) (int, error)
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Write(b []byte) (int, error)
}

type UDPConn interface {
	Close() error
	LocalAddr() net.Addr
	Read(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Write(b []byte) (int, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
}

type TCPListener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
	Shutdown()
}

// net2Backoff is a lneto.BackoffStrategy that yields goroutines at first and
// progressively sleeps longer as the number of consecutive backoffs increases.
func net2Backoff(consecutiveBackoffs uint) time.Duration {
	switch {
	case consecutiveBackoffs < 10:
		return lneto.BackoffFlagGosched
	case consecutiveBackoffs < 100:
		return 100 * time.Microsecond
	default:
		return time.Millisecond
	}
}

// --- tun.Device implementation ---

func (n *Net2) Name() (string, error)    { return "go2", nil }
func (n *Net2) File() *os.File           { return nil }
func (n *Net2) Events() <-chan tun.Event { return n.events }
func (n *Net2) MTU() (int, error)        { return n.mtu, nil }
func (n *Net2) BatchSize() int           { return 1 }

// Write feeds incoming IP packets (WireGuard → stack) into the lneto stack.
func (n *Net2) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if pkt := buf[offset:]; len(pkt) > 0 {
			n.sa.IngressIP(pkt) // errors dropped; stack silently filters bad packets
		}
	}
	return len(bufs), nil
}

// Read blocks until the stack has an outgoing IP packet to send to WireGuard.
func (n *Net2) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-n.pktOut
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}

func (n *Net2) Close() error {
	select {
	case <-n.done:
		return nil // already closed
	default:
	}
	close(n.done)
	close(n.events)
	close(n.pktOut)
	return nil
}

// egressLoop continuously polls EgressIP and delivers outgoing packets to pktOut.
func (n *Net2) egressLoop() {
	buf := make([]byte, n.mtu+100)
	var backoffs uint
	for {
		select {
		case <-n.done:
			return
		default:
		}
		cnt, _ := n.sa.EgressIP(buf)
		if cnt > 0 {
			pkt := make([]byte, cnt)
			copy(pkt, buf[:cnt])
			select {
			case n.pktOut <- pkt:
			case <-n.done:
				return
			}
			backoffs = 0
		} else {
			d := net2Backoff(backoffs)
			switch d {
			case lneto.BackoffFlagGosched:
				runtime.Gosched()
			case lneto.BackoffFlagNop:
				// nothing
			default:
				time.Sleep(d)
			}
			backoffs++
		}
	}
}

func CreateNetTUN2(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net2, error) {
	if mtu <= 0 {
		mtu = 1500
	}
	dev := &Net2{
		events:     make(chan tun.Event, 10),
		pktOut:     make(chan []byte, 64),
		done:       make(chan struct{}),
		mtu:        mtu,
		dnsServers: dnsServers,
	}

	var hwAddr [6]byte
	if _, err := crand.Read(hwAddr[:]); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUN2: rand MAC: %w", err)
	}
	hwAddr[0] &^= 0x01 // unicast
	hwAddr[0] |= 0x02  // locally administered

	var staticAddr4 [4]byte
	for _, addr := range localAddresses {
		if addr.Is4() {
			staticAddr4 = addr.As4()
			break
		}
	}

	var dnsServer netip.Addr
	if len(dnsServers) > 0 && dnsServers[0].Is4() {
		dnsServer = dnsServers[0]
	}

	var randSeed int64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &randSeed); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUN2: rand seed: %w", err)
	}

	err := dev.sa.Reset(xnet.StackConfig{
		HardwareAddress:   hwAddr,
		StaticAddress4:    staticAddr4,
		MTU:               uint16(mtu),
		Hostname:          "wg0",
		RandSeed:          randSeed,
		PassivePeers:      0, // no ARP passive learning needed for TUN
		ICMPQueueLimit:    4,
		MaxActiveTCPPorts: 256,
		MaxActiveUDPPorts: 256,
		DNSServer:         dnsServer,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUN2: stack reset: %w", err)
	}
	dev.blk = dev.sa.StackRetrying(net2Backoff)
	dev.sgo = dev.sa.StackGo(net2Backoff, xnet.StackGoConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           256,
			QueueSize:          8,
			TxBufSize:          32 << 10,
			RxBufSize:          32 << 10,
			EstablishedTimeout: 30 * time.Second,
			ClosingTimeout:     10 * time.Second,
		},
	})
	dev.events <- tun.EventUp
	go dev.egressLoop()
	return dev, dev, nil
}

// --- TCP ---

// socketResult extracts a typed result from a SocketNetip call.
// SocketNetip's TCP dial branch returns connection errors as the value (not err)
// to distinguish stack-level failures from protocol errors, so we handle both.
func socketResult[T any](v any, err error) (T, error) {
	var zero T
	if err != nil {
		return zero, err
	}
	if e, ok := v.(error); ok {
		return zero, e
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("socket: unexpected type %T", v)
	}
	return t, nil
}

func (n *Net2) dialTCPCtx(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	v, err := n.sgo.SocketNetip(ctx, "tcp4", syscall.AF_INET, syscall.SOCK_STREAM, netip.AddrPort{}, addr)
	return socketResult[TCPConn](v, err)
}

func (n *Net2) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	return n.dialTCPCtx(ctx, addr)
}

func (n *Net2) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (TCPConn, error) {
	if addr == nil {
		return n.dialTCPCtx(ctx, netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.dialTCPCtx(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

func (n *Net2) DialTCPAddrPort(addr netip.AddrPort) (TCPConn, error) {
	return n.dialTCPCtx(context.Background(), addr)
}

func (n *Net2) DialTCP(addr *net.TCPAddr) (TCPConn, error) {
	return n.DialContextTCP(context.Background(), addr)
}

// --- TCP listener ---

func (n *Net2) ListenTCPAddrPort(addr netip.AddrPort) (TCPListener, error) {
	v, err := n.sgo.SocketNetip(context.Background(), "tcp4", syscall.AF_INET, syscall.SOCK_STREAM, addr, netip.AddrPort{})
	return socketResult[TCPListener](v, err)
}

func (n *Net2) ListenTCP(addr *net.TCPAddr) (TCPListener, error) {
	if addr == nil {
		return n.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.ListenTCPAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

// --- UDP ---

func (n *Net2) ListenUDPAddrPort(laddr netip.AddrPort) (UDPConn, error) {
	v, err := n.sgo.SocketNetip(context.Background(), "udp4", syscall.AF_INET, syscall.SOCK_DGRAM, laddr, netip.AddrPort{})
	return socketResult[UDPConn](v, err)
}

func (n *Net2) ListenUDP(laddr *net.UDPAddr) (UDPConn, error) {
	if laddr == nil {
		return n.ListenUDPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(laddr.IP)
	return n.ListenUDPAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(laddr.Port)))
}

func (n *Net2) DialUDPAddrPort(laddr, raddr netip.AddrPort) (UDPConn, error) {
	v, err := n.sgo.SocketNetip(context.Background(), "udp4", syscall.AF_INET, syscall.SOCK_DGRAM, laddr, raddr)
	return socketResult[UDPConn](v, err)
}

func (n *Net2) DialUDP(laddr, raddr *net.UDPAddr) (UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip.Unmap(), uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip.Unmap(), uint16(raddr.Port))
	}
	return n.DialUDPAddrPort(la, ra)
}

// --- Ping ---

func (n *Net2) DialPingAddr(_, _ netip.Addr) (*PingConn, error) {
	return nil, errors.New("ping not implemented for Net2: PingConn is gvisor-coupled")
}

func (n *Net2) ListenPingAddr(_ netip.Addr) (*PingConn, error) {
	return nil, errors.New("ping not implemented for Net2: PingConn is gvisor-coupled")
}

func (n *Net2) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
	var la, ra netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	if raddr != nil {
		ra = raddr.addr
	}
	return n.DialPingAddr(la, ra)
}

func (n *Net2) ListenPing(laddr *PingAddr) (*PingConn, error) {
	var la netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	return n.ListenPingAddr(la)
}

// --- DNS ---

func (n *Net2) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []string{ip.String()}, nil
	}
	timeout := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < timeout {
			timeout = rem
		}
	}
	addrs, err := n.blk.DoLookupIP(host, timeout, 1)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host}
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out, nil
}

func (n *Net2) LookupHost(host string) ([]string, error) {
	return n.LookupContextHost(context.Background(), host)
}

// --- Generic Dial ---

var protoSplitter2 = regexp.MustCompile(`^(tcp|udp|ping)(4|6)?$`)

func (n *Net2) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	matches := protoSplitter2.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	acceptV4 := len(matches[2]) == 0 || matches[2] == "4"
	acceptV6 := len(matches[2]) == 0 || matches[2] == "6"

	var host string
	var port int
	if matches[1] == "ping" {
		host = address
	} else {
		var sport string
		var err error
		host, sport, err = net.SplitHostPort(address)
		if err != nil {
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		port, err = strconv.Atoi(sport)
		if err != nil || port < 0 || port > 65535 {
			return nil, &net.OpError{Op: "dial", Err: errNumericPort}
		}
	}

	allAddr, err := n.LookupContextHost(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	var addrs []netip.AddrPort
	for _, a := range allAddr {
		ip, err := netip.ParseAddr(a)
		if err == nil && ((ip.Is4() && acceptV4) || (ip.Is6() && acceptV6)) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}
		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			pd, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if pd.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, pd)
				defer cancel()
			}
		}

		var c net.Conn
		switch matches[1] {
		case "tcp":
			c, err = n.DialContextTCPAddrPort(dialCtx, addr)
		case "udp":
			c, err = n.DialUDPAddrPort(netip.AddrPort{}, addr)
		case "ping":
			c, err = n.DialPingAddr(netip.Addr{}, addr.Addr())
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	return nil, firstErr
}

func (n *Net2) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}
