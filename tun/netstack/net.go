/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"time"
)

// Net is the userspace networking API (Dial/Listen/DNS) layered over a backend
// [Stack]. It is backend-agnostic: [CreateNetTUN] wraps the gvisor backend and
// [CreateNetTUNLneto] wraps the lneto backend, but both return a *Net with the
// same surface so callers can swap backends transparently.
//
// The backend object also implements [golang.zx2c4.com/wireguard/tun.Device]
// (returned as the first value from the constructors) and is the data plane that
// moves IP packets to and from WireGuard.
type Net struct {
	stack Stack
}

// Stack is the backend-specific primitive set that [Net] delegates to. Both the
// gvisor netTun and the lneto stack implement it. Higher-level conveniences
// (the *net.TCPAddr/*net.UDPAddr/*PingAddr overloads, generic Dial/DialContext,
// LookupHost) live once on [Net] and are written in terms of these primitives.
type Stack interface {
	DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (TCPConn, error)
	DialTCPAddrPort(addr netip.AddrPort) (TCPConn, error)
	ListenTCPAddrPort(addr netip.AddrPort) (TCPListener, error)
	DialUDPAddrPort(laddr, raddr netip.AddrPort) (UDPConn, error)
	ListenUDPAddrPort(laddr netip.AddrPort) (UDPConn, error)
	DialPingAddr(laddr, raddr netip.Addr) (PingConn, error)
	ListenPingAddr(laddr netip.Addr) (PingConn, error)
	LookupContextHost(ctx context.Context, host string) ([]string, error)
}

// TCPConn is the connection type returned by the TCP dial methods. gvisor's
// *gonet.TCPConn and lneto's TCP connection both satisfy it.
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

// UDPConn is the connection type returned by the UDP dial/listen methods.
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

// TCPListener is the listener type returned by the TCP listen methods.
type TCPListener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
	Shutdown()
}

// PingConn is the ICMP "ping" connection returned by the ping methods. It is both a
// [net.Conn] (Read/Write against the dialed peer) and supports addressed I/O via
// ReadFrom/WriteTo. The gvisor backend returns a concrete implementation; the lneto
// backend does not implement ping and returns an error.
type PingConn interface {
	net.Conn
	ReadFrom(p []byte) (int, net.Addr, error)
	WriteTo(p []byte, addr net.Addr) (int, error)
}

// PingAddr is a [net.Addr] for the "ping" pseudo-networks. It wraps a bare
// [netip.Addr] (no port) and is backend-neutral.
type PingAddr struct{ addr netip.Addr }

func (ia PingAddr) String() string {
	return ia.addr.String()
}

func (ia PingAddr) Network() string {
	if ia.addr.Is4() {
		return "ping4"
	} else if ia.addr.Is6() {
		return "ping6"
	}
	return "ping"
}

func (ia PingAddr) Addr() netip.Addr {
	return ia.addr
}

func PingAddrFromAddr(addr netip.Addr) *PingAddr {
	return &PingAddr{addr}
}

// --- TCP ---

func (n *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	return n.stack.DialContextTCPAddrPort(ctx, addr)
}

func (n *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (TCPConn, error) {
	if addr == nil {
		return n.stack.DialContextTCPAddrPort(ctx, netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

func (n *Net) DialTCPAddrPort(addr netip.AddrPort) (TCPConn, error) {
	return n.stack.DialTCPAddrPort(addr)
}

func (n *Net) DialTCP(addr *net.TCPAddr) (TCPConn, error) {
	if addr == nil {
		return n.stack.DialTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.stack.DialTCPAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

func (n *Net) ListenTCPAddrPort(addr netip.AddrPort) (TCPListener, error) {
	return n.stack.ListenTCPAddrPort(addr)
}

func (n *Net) ListenTCP(addr *net.TCPAddr) (TCPListener, error) {
	if addr == nil {
		return n.stack.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.stack.ListenTCPAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

// --- UDP ---

func (n *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (UDPConn, error) {
	return n.stack.DialUDPAddrPort(laddr, raddr)
}

func (n *Net) ListenUDPAddrPort(laddr netip.AddrPort) (UDPConn, error) {
	return n.stack.ListenUDPAddrPort(laddr)
}

func (n *Net) DialUDP(laddr, raddr *net.UDPAddr) (UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip.Unmap(), uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip.Unmap(), uint16(raddr.Port))
	}
	return n.stack.DialUDPAddrPort(la, ra)
}

func (n *Net) ListenUDP(laddr *net.UDPAddr) (UDPConn, error) {
	return n.DialUDP(laddr, nil)
}

// --- Ping ---

func (n *Net) DialPingAddr(laddr, raddr netip.Addr) (PingConn, error) {
	return n.stack.DialPingAddr(laddr, raddr)
}

func (n *Net) ListenPingAddr(laddr netip.Addr) (PingConn, error) {
	return n.stack.ListenPingAddr(laddr)
}

func (n *Net) DialPing(laddr, raddr *PingAddr) (PingConn, error) {
	var la, ra netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	if raddr != nil {
		ra = raddr.addr
	}
	return n.stack.DialPingAddr(la, ra)
}

func (n *Net) ListenPing(laddr *PingAddr) (PingConn, error) {
	var la netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	return n.stack.ListenPingAddr(la)
}

// --- DNS ---

func (n *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return n.stack.LookupContextHost(ctx, host)
}

func (n *Net) LookupHost(host string) ([]string, error) {
	return n.stack.LookupContextHost(context.Background(), host)
}

// --- Generic Dial ---

var protoSplitter = regexp.MustCompile(`^(tcp|udp|ping)(4|6)?$`)

func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	var acceptV4, acceptV6 bool
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	} else if len(matches[2]) == 0 {
		acceptV4 = true
		acceptV6 = true
	} else {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}
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
	for _, addr := range allAddr {
		ip, err := netip.ParseAddr(addr)
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
		var cancel context.CancelFunc
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
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
		if cancel != nil {
			// This cancel belongs to a function-local context so cancel required to avoid leaks.
			cancel()
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

func (n *Net) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

// --- shared helpers ---

var (
	errNoSuchHost                   = errors.New("no such host")
	errLameReferral                 = errors.New("lame referral")
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")
	errServerMisbehaving            = errors.New("server misbehaving")
	errInvalidDNSResponse           = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")
	errCanceled                     = errors.New("operation was canceled")
	errTimeout                      = errors.New("i/o timeout")
	errNumericPort                  = errors.New("port must be numeric")
	errNoSuitableAddress            = errors.New("no suitable address found")
	errMissingAddress               = errors.New("missing address")
)

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}

func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errTimeout
	}
	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}
