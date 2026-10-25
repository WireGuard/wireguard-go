//go:build wglneto

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
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// TestNet2_Construct is a regression test: the previous CreateNetTUNLneto omitted
// TCPPoolConfig.NewBackoff, which made StackGo panic at construction.
func TestNet2_Construct(t *testing.T) {
	dev, net2, err := CreateNetTUNLneto(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1500,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if net2 == nil {
		t.Fatal("nil Net")
	}
	select {
	case ev := <-dev.Events():
		if ev != tun.EventUp {
			t.Fatalf("want EventUp, got %v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no EventUp event")
	}
}

// TestNet2_CloseRace stresses the Read/Write/Close interaction that previously
// panicked with "send on closed channel". Run with -race.
func TestNet2_CloseRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		dev, _, err := CreateNetTUNLneto(
			[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
			nil, 1500,
		)
		if err != nil {
			t.Fatal(err)
		}
		<-dev.Events() // drain EventUp

		var wg sync.WaitGroup
		// Reader: must return os.ErrClosed once Close fires, never panic.
		wg.Add(1)
		go func() {
			defer wg.Done()
			bufs := [][]byte{make([]byte, 2048)}
			sizes := []int{0}
			for {
				_, err := dev.Read(bufs, sizes, 0)
				if errors.Is(err, os.ErrClosed) {
					return
				}
			}
		}()
		// Writer: feed junk ingress concurrently with Close.
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := make([]byte, 40)
			pkt[0] = 0x45 // IPv4, IHL 5
			for j := 0; j < 1000; j++ {
				if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
					return
				}
			}
		}()

		time.Sleep(time.Millisecond)
		if err := dev.Close(); err != nil {
			t.Fatal(err)
		}
		// Double close must be safe (no panic).
		if err := dev.Close(); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
	}
}

// TestNet2_ListenTCPPort0 covers gap D: listening on port 0 must auto-assign an
// ephemeral port instead of failing (the library previously returned ErrZeroSource).
func TestNet2_ListenTCPPort0(t *testing.T) {
	dev, net2, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	<-dev.Events()

	ln, err := net2.ListenTCPAddrPort(netip.AddrPort{})
	if err != nil {
		t.Fatal("listen on port 0:", err)
	}
	defer ln.Close()
	if a, ok := ln.Addr().(*net.TCPAddr); !ok || a.Port == 0 {
		t.Fatalf("expected an auto-assigned ephemeral port, got %v", ln.Addr())
	}
}

// TestNet2_UDPEcho wires two Net2 instances back-to-back and performs a connected
// UDP dial against a UDP PacketConn listener, exercising the UDP socket paths.
func TestNet2_UDPEcho(t *testing.T) {
	const (
		addrA = "10.0.0.1"
		addrB = "10.0.0.2"
		port  = 9999
	)
	devA, netA, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrA)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
	}()

	srv, err := netB.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("listen udp:", err)
	}
	defer srv.Close()

	const msg = "hello over lneto udp"
	srvDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		srv.SetDeadline(time.Now().Add(5 * time.Second))
		n, from, err := srv.ReadFrom(buf)
		if err != nil {
			srvDone <- err
			return
		}
		_, err = srv.WriteTo(buf[:n], from) // echo back to sender
		srvDone <- err
	}()

	cli, err := netA.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("dial udp:", err)
	}
	defer cli.Close()
	cli.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cli.Write([]byte(msg)); err != nil {
		t.Fatal("udp write:", err)
	}
	echo := make([]byte, 512)
	n, err := cli.Read(echo)
	if err != nil {
		t.Fatal("udp read echo:", err)
	}
	if string(echo[:n]) != msg {
		t.Fatalf("udp echo mismatch: want %q got %q", msg, string(echo[:n]))
	}
	if err := <-srvDone; err != nil {
		t.Fatal("udp server:", err)
	}
}

// pump forwards IP frames produced by src into dst until src is closed.
func pump(src, dst tun.Device) {
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	for {
		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}
		out := make([]byte, sizes[0])
		copy(out, bufs[0][:sizes[0]])
		if _, err := dst.Write([][]byte{out}, 0); err != nil {
			return
		}
	}
}

// TestNet2_TCPEcho wires two Net2 instances back-to-back (one's egress is the
// other's ingress) and performs a TCP dial + echo, exercising the egress poll,
// the dial path, and the listener/accept path end-to-end for both IPv4 and IPv6.
func TestNet2_TCPEcho(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) { testTCPEcho(t, "10.0.0.1", "10.0.0.2") })
	t.Run("ipv6", func(t *testing.T) { testTCPEcho(t, "fd00::1", "fd00::2") })
}

func testTCPEcho(t *testing.T, addrA, addrB string) {
	const port = 1234
	devA, netA, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrA)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()

	ln, err := netB.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("listen:", err)
	}
	// Teardown order matters: stop ingress (close devices → pumps exit) BEFORE
	// closing the listener, since tcp.Listener.Close is not synchronized against
	// the stack's ingress demux in the lneto library (see review notes).
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
		ln.Close()
	}()

	const msg = "hello over lneto tcp"
	srvDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(msg))
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var got int
		for got < len(msg) {
			n, err := conn.Read(buf[got:])
			if err != nil {
				srvDone <- err
				return
			}
			got += n
		}
		_, err = conn.Write(buf[:got]) // echo back
		srvDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := netA.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("dial:", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal("write:", err)
	}
	echo := make([]byte, len(msg))
	got := 0
	for got < len(msg) {
		n, err := conn.Read(echo[got:])
		if err != nil {
			t.Fatal("read echo:", err)
		}
		got += n
	}
	if string(echo) != msg {
		t.Fatalf("echo mismatch: want %q got %q", msg, string(echo))
	}
	if err := <-srvDone; err != nil {
		t.Fatal("server:", err)
	}
}
