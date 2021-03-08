/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type netTun struct {
	stack          *stack.Stack
	dispatcher     stack.NetworkDispatcher
	events         chan tun.Event
	incomingPacket chan buffer.VectorisedView
	mtu            int
	dnsServers     []net.IP
	resolver       *net.Resolver
	hasV4, hasV6   bool
}
type endpoint netTun
type Net netTun

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *endpoint) MTU() uint32 {
	mtu, err := (*netTun)(e).MTU()
	if err != nil {
		panic(err)
	}
	return uint32(mtu)
}

func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*endpoint) Wait() {}

func (e *endpoint) WritePacket(_ stack.RouteInfo, _ *stack.GSO, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	e.incomingPacket <- buffer.NewVectorisedView(pkt.Size(), pkt.Views())
	return nil
}

func (e *endpoint) WritePackets(stack.RouteInfo, *stack.GSO, stack.PacketBufferList, tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	panic("not implemented")
}

func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *endpoint) AddHeader(tcpip.LinkAddress, tcpip.LinkAddress, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func CreateNetTUN(localAddresses, dnsServers []net.IP, mtu int) (tun.Device, *Net, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	}
	dev := &netTun{
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan buffer.VectorisedView),
		dnsServers:     dnsServers,
		mtu:            mtu,
	}
	tcpipErr := dev.stack.CreateNIC(1, (*endpoint)(dev))
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		if ip4 := ip.To4(); ip4 != nil {
			tcpipErr = dev.stack.AddAddress(1, ipv4.ProtocolNumber, tcpip.Address(ip4))
			if tcpipErr != nil {
				return nil, nil, fmt.Errorf("AddAddress(%v): %v", ip4, tcpipErr)
			}
			dev.hasV4 = true
		} else {
			tcpipErr = dev.stack.AddAddress(1, ipv6.ProtocolNumber, tcpip.Address(ip))
			if tcpipErr != nil {
				return nil, nil, fmt.Errorf("AddAddress(%v): %v", ip4, tcpipErr)
			}
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	dev.resolver = &net.Resolver{
		PreferGo: true,
		Dial:     (*Net)(dev).dialDNS,
	}

	dev.events <- tun.EventUp
	return dev, (*Net)(dev), nil
}

func (tun *netTun) Name() (string, error) {
	return "go", nil
}

func (tun *netTun) File() *os.File {
	return nil
}

func (tun *netTun) Events() chan tun.Event {
	return tun.events
}

func (tun *netTun) Read(buf []byte, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	return view.Read(buf[offset:])
}

func (tun *netTun) Write(buf []byte, offset int) (int, error) {
	packet := buf[offset:]
	if len(packet) == 0 {
		return 0, nil
	}

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Data: buffer.NewVectorisedView(len(packet), []buffer.View{buffer.NewViewFromBytes(packet)})})
	switch packet[0] >> 4 {
	case 4:
		tun.dispatcher.DeliverNetworkPacket("", "", ipv4.ProtocolNumber, pkb)
	case 6:
		tun.dispatcher.DeliverNetworkPacket("", "", ipv6.ProtocolNumber, pkb)
	}

	return len(buf), nil
}

func (tun *netTun) Flush() error {
	return nil
}

func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)

	if tun.events != nil {
		close(tun.events)
	}
	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}
	return nil
}

func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

func convertToFullAddr(ip net.IP, port int) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	if ip4 := ip.To4(); ip4 != nil {
		return tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.Address(ip4),
			Port: uint16(port),
		}, ipv4.ProtocolNumber
	} else {
		return tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.Address(ip),
			Port: uint16(port),
		}, ipv6.ProtocolNumber
	}
}

func (net *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		panic("todo: deal with auto addr semantics for nil addr")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

func (net *Net) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		panic("todo: deal with auto addr semantics for nil addr")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.DialTCP(net.stack, fa, pn)
}

func (net *Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		panic("todo: deal with auto addr semantics for nil addr")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *Net) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr != nil {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(laddr.IP, laddr.Port)
		lfa = &addr
	}
	if raddr != nil {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(raddr.IP, raddr.Port)
		rfa = &addr
	}
	return gonet.DialUDP(net.stack, lfa, rfa, pn)
}

var (
	errCanceled          = errors.New("operation was canceled")
	errTimeout           = errors.New("i/o timeout")
	errNumericPort       = errors.New("port must be numeric")
	errNoSuitableAddress = errors.New("no suitable address found")
	errMissingAddress    = errors.New("missing address")
)

func (net *Net) Resolver() *net.Resolver { return net.resolver }

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

func (tnet *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	var acceptV4, acceptV6, useUDP bool
	if len(network) == 3 {
		acceptV4 = true
		acceptV6 = true
	} else if len(network) == 4 {
		acceptV4 = network[3] == '4'
		acceptV6 = network[3] == '6'
	}
	if !acceptV4 && !acceptV6 {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	if network[:3] == "udp" {
		useUDP = true
	} else if network[:3] != "tcp" {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errNumericPort}
	}

	var addrs []net.IP
	if addr := net.ParseIP(host); addr != nil {
		addrs = []net.IP{addr}
	} else {
		allAddr, err := tnet.resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		for _, addr := range allAddr {
			if strings.IndexByte(addr, ':') != -1 && acceptV6 {
				addrs = append(addrs, net.ParseIP(addr))
			} else if strings.IndexByte(addr, '.') != -1 && acceptV4 {
				addrs = append(addrs, net.ParseIP(addr))
			}
		}
		if len(addrs) == 0 && len(allAddr) != 0 {
			return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
		}
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
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		var c net.Conn
		if useUDP {
			c, err = tnet.DialUDP(nil, &net.UDPAddr{IP: addr, Port: port})
		} else {
			c, err = tnet.DialContextTCP(dialCtx, &net.TCPAddr{IP: addr, Port: port})
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

func (tnet *Net) Dial(network, address string) (net.Conn, error) {
	return tnet.DialContext(context.Background(), network, address)
}

func (tnet *Net) dialDNS(ctx context.Context, network, address string) (net.Conn, error) {
	if len(tnet.dnsServers) == 0 {
		return tnet.DialContext(ctx, network, address)
	}

	dnsIPs := make(map[string]struct{}, len(tnet.dnsServers))
	for _, dnsServer := range tnet.dnsServers {
		ipAddress := dnsServer.String()
		if host, _, err := net.SplitHostPort(address); err != nil && host == ipAddress {
			return tnet.DialContext(ctx, network, address)
		}
		dnsIPs[ipAddress] = struct{}{}
	}

	var lastErr error
	for ipAddress := range dnsIPs {
		conn, err := tnet.DialContext(ctx, network, net.JoinHostPort(ipAddress, "53"))
		if err != nil {
			if nerr, ok := err.(*net.OpError); ok {
				lastErr = nerr
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, lastErr
}
