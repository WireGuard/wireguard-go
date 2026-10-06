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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
	"github.com/soypat/lneto/x/xnet"
	"golang.zx2c4.com/wireguard/tun"
)

func CreateNetTUNLneto(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error) {
	if mtu <= 0 {
		mtu = 1500
	}
	if mtu > 65535 {
		return nil, nil, fmt.Errorf("CreateNetTUNLneto: mtu %d exceeds maximum 65535", mtu)
	}
	dev := &lnetoStack{
		events:     make(chan tun.Event, 10),
		closed:     make(chan struct{}),
		mtu:        mtu,
		dnsServers: dnsServers,
	}

	var hwAddr [6]byte
	if _, err := crand.Read(hwAddr[:]); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUNLneto: rand MAC: %w", err)
	}
	hwAddr[0] &^= 0x01 // unicast
	hwAddr[0] |= 0x02  // locally administered

	// Pick the first IPv4 and first IPv6 local address; track which families are
	// configured (mirrors gVisor's hasV4/hasV6).
	var staticAddr4 [4]byte
	var staticAddr6 [16]byte
	hasIPV6 := false
	for _, addr := range localAddresses {
		if addr.Is4() && !dev.hasV4 {
			staticAddr4 = addr.As4()
			dev.hasV4 = true
		} else if addr.Is6() && !hasIPV6 {
			staticAddr6 = addr.As16()
			hasIPV6 = true
		}
	}

	// DNS server: prefer IPv4 (the stack's lookup path is currently IPv4-only),
	// fall back to the first IPv6 server.
	var dnsServer netip.Addr
	for _, d := range dnsServers {
		if d.Is4() {
			dnsServer = d
			break
		}
	}
	if !dnsServer.IsValid() {
		for _, d := range dnsServers {
			if d.Is6() {
				dnsServer = d
				break
			}
		}
	}

	var randSeed int64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &randSeed); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUNLneto: rand seed: %w", err)
	}

	cfg := xnet.StackConfig{
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
	}
	if hasIPV6 {
		cfg.StaticAddress6 = staticAddr6
		cfg.IPv6Stack = xnet.DefaultStack6()
	}
	// NOTE: ICMP is intentionally NOT enabled here. On a TUN there is no link layer,
	// so MAC resolution must be skipped: IPv4 ARP is gated off by leaving the subnet
	// unset, and IPv6 NDP is gated off by leaving ICMPv6 unregistered. Enabling ICMP
	// would make DialTCP6/DialUDP6 emit Neighbor Solicitations that are never answered
	// on a TUN, breaking IPv6 dialing. Ping support (which needs ICMP) is a separate
	// follow-up that must reconcile this.
	if err := dev.sa.Reset(cfg); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUNLneto: stack reset: %w", err)
	}

	// Backoff selection. A native single-threaded runtime (GOMAXPROCS==1) only yields
	// cooperatively, because sleeping the poll would starve egress — there is no other
	// thread to drain it. js/wasm is also single-threaded but is the opposite case: it
	// MUST sleep so the runtime hands control back to the browser event loop (a bare
	// Gosched there starves all WebSocket/WireGuard I/O and freezes the tab). So js,
	// like the multi-threaded case, keeps the exponential sleeping backoffs — applied
	// to BOTH the stack poll and every per-connection RWBackoff.
	baseStack := defaultStackBackoff
	newTCPBackoff := func() lneto.BackoffStrategy { return defaultTCPBackoff }
	if runtime.GOMAXPROCS(0) == 1 && runtime.GOOS != "js" {
		baseStack = backoffYield
		newTCPBackoff = func() lneto.BackoffStrategy { return backoffYield }
	}
	irq, backoff := interruptBackoff(baseStack)
	dev.backoff = backoff
	dev.backoffirq = irq

	dev.sgo = dev.sa.StackGo(backoff, xnet.StackGoConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           256,
			QueueSize:          8,
			TxBufSize:          32 << 10,
			RxBufSize:          32 << 10,
			EstablishedTimeout: 30 * time.Second,
			ClosingTimeout:     10 * time.Second,
			NewBackoff:         newTCPBackoff, // required: StackGo panics if nil.
			NanoTime:           nanotime,
			// Give each connection an adaptive RTO timer (RFC 6298 style) instead
			// of the fixed-interval default, so retransmissions track the measured
			// RTT rather than firing on a worst-case constant.
			NewPolicy: func() tcp.Policy {
				rto := new(rto.Timer)
				rto.Configure(nanotime)
				return rto
			},
		},
		TCPDialTimeout: time.Second,
		TCPDialRetries: 30,
	})
	dev.events <- tun.EventUp
	return dev, &Net{stack: dev}, nil
}

// nanotime is the monotonic clock handed to the stack's TCP timers. It is only
// ever used to measure elapsed time (RTT samples, RTO expiry), so the absolute
// epoch is irrelevant.
func nanotime() int64 {
	return time.Now().UnixNano()
}

// lnetoStack is a lneto-backed userspace network stack that implements both
// [tun.Device] (for WireGuard integration) and a networking API (Dial/Listen/DNS).
//
// Packet flow:
//   - Ingress (WireGuard → stack): [lnetoStack.Write] calls [xnet.StackAsync.IngressIP],
//     then pokes the backoff irq so a blocked [lnetoStack.Read] wakes immediately.
//   - Egress  (stack → WireGuard): [lnetoStack.Read] polls [xnet.StackAsync.EgressIP]
//     directly, sleeping on an interruptible backoff between empty polls.
//
// Unlike gVisor's channel.Endpoint there is no native egress notification hook, so
// egress is driven by Read's poll loop. The backoff is interruptible (woken by
// [lnetoStack.interrupt]) and GOMAXPROCS-aware: on a single-threaded runtime it only
// yields cooperatively (sleeping would starve the poll), otherwise it sleeps with
// exponential backoff. This mirrors the proven go-net design.
//
// Lifecycle: created by [CreateNetTUNLneto], torn down by [lnetoStack.Close] which closes
// the closed channel (unblocking Read and any blocking socket op) and events.
type lnetoStack struct {
	sa  xnet.StackAsync
	sgo xnet.StackGo // wraps sa; created once in CreateNetTUNLneto

	// events carries TUN state changes (e.g. EventUp) consumed by WireGuard's device loop.
	events chan tun.Event

	// backoff is the interruptible stack-protocol backoff shared with blk/sgo and
	// used by Read's egress poll. backoffirq wakes a sleeping backoff the moment new
	// work arrives (ingress packet, socket call) via interrupt.
	backoff    lneto.BackoffStrategy
	backoffirq chan<- event

	// closed is closed once by Close to unblock Read and signal shutdown.
	closed    chan struct{}
	closeOnce sync.Once

	mtu        int
	dnsServers []netip.Addr
	hasV4      bool
}

type event struct{}

// interruptBackoff wraps a [lneto.BackoffStrategy] so its sleep can be cut short by
// a write to the returned irq channel. Each call builds its own timer so concurrent
// callers (Read's poll loop and blocking socket ops) do not race on a shared one;
// the capacity-1 irq is shared, so one interrupt wakes exactly one sleeper, which is
// the intended best-effort behavior. The returned strategy always reports
// [lneto.BackoffFlagNop] because the yield is performed entirely inside the wrapper.
func interruptBackoff(backoff lneto.BackoffStrategy) (interrupt chan<- event, _ lneto.BackoffStrategy) {
	irq := make(chan event, 1)
	wrapped := func(consecutiveBackoffs uint) time.Duration {
		switch d := backoff(consecutiveBackoffs); d {
		case lneto.BackoffFlagGosched:
			runtime.Gosched()
		case lneto.BackoffFlagNop:
			// Do nothing.
		default:
			timer := time.NewTimer(d) // per-call: callers must not share a timer.
			select {
			case <-irq:
				if !timer.Stop() && len(timer.C) > 0 {
					<-timer.C
				}
			case <-timer.C:
			}
		}
		return lneto.BackoffFlagNop // yield handled here; signal caller to do nothing.
	}
	return irq, wrapped
}

// defaultStackBackoff is the idle backoff for stack protocol loops (DHCP, DNS, the
// egress poll, ...) on multi-threaded runtimes: exponential from 100µs up to 20ms.
func defaultStackBackoff(consecutiveBackoffs uint) time.Duration {
	const (
		minWait  = 100 * time.Microsecond
		maxWait  = 20 * time.Millisecond
		maxShift = 15

		_compileTimeOverflowCheck = minWait << maxShift
	)
	sleep := minWait << min(consecutiveBackoffs, maxShift)
	if sleep > maxWait {
		sleep = maxWait
	}
	return sleep
}

// defaultTCPBackoff is the per-connection read/write retry backoff for TCP streams.
// Shorter range than defaultStackBackoff to keep interactive sessions responsive.
func defaultTCPBackoff(consecutiveBackoffs uint) time.Duration {
	const (
		minWait  = 10 * time.Microsecond
		maxWait  = 1 * time.Millisecond
		maxShift = 10

		_compileTimeOverflowCheck = minWait << maxShift
	)
	sleep := minWait << min(consecutiveBackoffs, maxShift)
	if sleep > maxWait {
		sleep = maxWait
	}
	return sleep
}

// backoffYield never sleeps; it only yields cooperatively. Used on GOMAXPROCS==1
// where sleeping the poll goroutine would starve egress processing.
func backoffYield(consecutiveBackoffs uint) time.Duration {
	return lneto.BackoffFlagGosched
}

// interrupt wakes one sleeper blocked in the interruptible backoff (Read's poll loop
// or a blocking socket op). Non-blocking and safe to call from any goroutine.
func (n *lnetoStack) interrupt() {
	select {
	case n.backoffirq <- event{}:
	default:
	}
}

// --- tun.Device implementation ---

func (n *lnetoStack) Name() (string, error)    { return "go2", nil }
func (n *lnetoStack) File() *os.File           { return nil }
func (n *lnetoStack) Events() <-chan tun.Event { return n.events }
func (n *lnetoStack) MTU() (int, error)        { return n.mtu, nil }
func (n *lnetoStack) BatchSize() int           { return 1 }

// Write feeds incoming IP packets (WireGuard → stack) into the lneto stack.
func (n *lnetoStack) Write(bufs [][]byte, offset int) (int, error) {
	wrote := false
	for _, buf := range bufs {
		if pkt := buf[offset:]; len(pkt) > 0 {
			n.sa.IngressIP(pkt) // errors dropped; stack silently filters bad packets
			debugIPPacket(false, pkt)
			wrote = true
		}
	}
	if wrote {
		n.interrupt() // wake Read: ingress often produces an immediate egress reply.
	}
	return len(bufs), nil
}

// Read blocks until the stack has an outgoing IP packet to send to WireGuard, polling
// EgressIP and sleeping on the interruptible backoff between empty polls. It writes
// directly into the caller's buffer (no intermediate copy). Returns os.ErrClosed once
// Close has been called.
func (n *lnetoStack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	dst := bufs[0][offset:]
	var backoffs uint
	for {
		select {
		case <-n.closed:
			return 0, os.ErrClosed
		default:
		}
		cnt, _ := n.sa.EgressIP(dst)
		if cnt > 0 {
			sizes[0] = cnt
			debugIPPacket(true, dst[:cnt])
			return 1, nil
		}
		n.backoff.Do(backoffs) // interruptible; returns promptly when interrupt fires.
		backoffs++
	}
}

func (n *lnetoStack) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed) // unblock Read.
		n.interrupt()   // wake a backoff sleeper so it observes closed promptly.
		close(n.events)
	})
	return nil
}

var _ Stack = (*lnetoStack)(nil)

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

// socket wraps sgo.SocketNetip. It selects the IPv4 or IPv6 network/family from the
// family-bearing endpoint (the remote for a dial, otherwise the local bind), and pokes
// the egress poll on entry and exit because connection setup (handshake, NDP/ARP)
// queues egress frames that Read must drain promptly.
func (n *lnetoStack) socket(ctx context.Context, proto string, sotype int, laddr, raddr netip.AddrPort) (any, error) {
	fam := raddr
	if !fam.IsValid() {
		fam = laddr
	}
	network := proto + "4"
	family := syscall.AF_INET
	if fam.Addr().Is6() {
		network = proto + "6"
		family = syscall.AF_INET6
	}
	n.interrupt()
	defer n.interrupt()
	return n.sgo.SocketNetip(ctx, network, family, sotype, laddr, raddr)
}

func (n *lnetoStack) dialTCPCtx(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	v, err := n.socket(ctx, "tcp", syscall.SOCK_STREAM, netip.AddrPort{}, addr)
	return socketResult[TCPConn](v, err)
}

func (n *lnetoStack) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	return n.dialTCPCtx(ctx, addr)
}

func (n *lnetoStack) DialTCPAddrPort(addr netip.AddrPort) (TCPConn, error) {
	return n.dialTCPCtx(context.Background(), addr)
}

// --- TCP listener ---

func (n *lnetoStack) ListenTCPAddrPort(addr netip.AddrPort) (TCPListener, error) {
	v, err := n.socket(context.Background(), "tcp", syscall.SOCK_STREAM, addr, netip.AddrPort{})
	return socketResult[TCPListener](v, err)
}

// --- UDP ---

func (n *lnetoStack) ListenUDPAddrPort(laddr netip.AddrPort) (UDPConn, error) {
	v, err := n.socket(context.Background(), "udp", syscall.SOCK_DGRAM, laddr, netip.AddrPort{})
	return socketResult[UDPConn](v, err)
}

func (n *lnetoStack) DialUDPAddrPort(laddr, raddr netip.AddrPort) (UDPConn, error) {
	v, err := n.socket(context.Background(), "udp", syscall.SOCK_DGRAM, laddr, raddr)
	return socketResult[UDPConn](v, err)
}

// --- Ping ---

func (n *lnetoStack) DialPingAddr(_, _ netip.Addr) (PingConn, error) {
	return nil, errors.New("ping not implemented for lnetoStack")
}

func (n *lnetoStack) ListenPingAddr(_ netip.Addr) (PingConn, error) {
	return nil, errors.New("ping not implemented for lnetoStack")
}

// --- DNS ---

// dnsError wraps a lookup failure as a *net.DNSError, flagging timeouts when the
// underlying error reports them. Mirrors the error shape produced by the gvisor Net.
func dnsError(host string, err error) *net.DNSError {
	de := &net.DNSError{Err: err.Error(), Name: host}
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		de.IsTimeout = true
	}
	return de
}

// LookupContextHost resolves host to a list of IP strings, matching the behaviour of
// the gvisor Net: literal IPs (with IPv6 zone stripping) pass through; empty or
// non-domain hosts and stacks with no address family return an IsNotFound DNSError;
// A and AAAA are queried for the enabled families and, when IPv6 is enabled, IPv6
// results are ordered first (no RFC 6724).
func (n *lnetoStack) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!n.hasV4 && !n.sa.IsIPv6Enabled()) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	// Strip any IPv6 zone before attempting to parse a literal address.
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}
	if !isDomainName(host) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}

	timeout := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < timeout {
			timeout = rem
		}
	}
	blk := n.sa.StackBlocking(n.backoff)

	var addrsV4, addrsV6 []netip.Addr
	var lastErr error
	if n.hasV4 {
		if a, err := blk.DoLookupIPType(host, timeout, dns.TypeA); err != nil {
			lastErr = dnsError(host, err)
		} else {
			addrsV4 = a
		}
	}
	if n.sa.IsIPv6Enabled() {
		if a, err := blk.DoLookupIPType(host, timeout, dns.TypeAAAA); err != nil {
			if lastErr == nil {
				lastErr = dnsError(host, err)
			}
		} else {
			addrsV6 = a
		}
	}

	// IPv6 first when enabled, mirroring the gvisor Net's ordering.
	var addrs []netip.Addr
	if n.sa.IsIPv6Enabled() {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}
	if len(addrs) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out, nil
}
