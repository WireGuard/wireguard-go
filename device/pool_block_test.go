/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// newCappedDevice brings up a Device whose pools are capped, with a single peer
// that has no endpoint and therefore never completes a handshake.
func newCappedDevice(t *testing.T, cap uint32) (*Device, *Peer) {
	t.Helper()

	prev := PreallocatedBuffersPerPool
	SetPreallocatedBuffersPerPool(cap)
	t.Cleanup(func() { SetPreallocatedBuffersPerPool(prev) })

	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	peerSk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("peer private key: %v", err)
	}
	peerPk := peerSk.publicKey()

	binds := bindtest.NewChannelBinds()
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], NewLogger(LogLevelError, "capped: "))
	t.Cleanup(dev.Close)

	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=1.0.0.2/32\n",
		hex.EncodeToString(sk[:]), hex.EncodeToString(peerPk[:]))
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("configure device: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bring device up: %v", err)
	}

	peer := dev.LookupPeer(peerPk)
	if peer == nil {
		t.Fatal("peer not configured")
	}
	return dev, peer
}

// drainMessageBuffers empties the message buffer pool and hands the buffers back
// when the test ends. Without the hand-back, Device.Close would wait forever on
// the device routines that are parked in the empty pool.
func drainMessageBuffers(t *testing.T, dev *Device) {
	t.Helper()

	var held []*[MaxMessageSize]byte
	for {
		buf, ok := dev.TryGetMessageBuffer()
		if !ok {
			break
		}
		held = append(held, buf)
	}
	if len(held) == 0 {
		t.Fatal("pool was already empty, the cap is not in effect")
	}
	t.Cleanup(func() {
		for _, buf := range held {
			dev.PutMessageBuffer(buf)
		}
	})
}

func TestWaitPoolTryGetAtCapacity(t *testing.T) {
	p := NewWaitPool(1, func() any { return new([1]byte) })

	first, ok := p.TryGet()
	if !ok {
		t.Fatal("TryGet on an empty tracked pool must succeed")
	}
	if _, ok := p.TryGet(); ok {
		t.Fatal("TryGet at capacity must report false instead of waiting")
	}

	p.Put(first)
	if _, ok := p.TryGet(); !ok {
		t.Fatal("TryGet must succeed again once a buffer is returned")
	}
}

func TestWaitPoolTryGetUntracked(t *testing.T) {
	p := NewWaitPool(0, func() any { return new([1]byte) })
	for i := 0; i < 3; i++ {
		if _, ok := p.TryGet(); !ok {
			t.Fatal("TryGet on an uncapped pool must always succeed")
		}
	}
}

// TestSendKeepaliveWithExhaustedPool is the regression test for the proxy
// deadlock: a keepalive that waits for a buffer does so inside a timer callback
// holding the timer's runningLock, which makes Peer.Stop - and therefore peer
// removal and Device.Close - impossible to complete.
func TestSendKeepaliveWithExhaustedPool(t *testing.T) {
	dev, peer := newCappedDevice(t, 64)

	// Bringing the device up can already have staged a packet; SendKeepalive is
	// a no-op while the staged queue is non-empty.
	peer.FlushStagedPackets()
	if len(peer.queue.staged) != 0 {
		t.Fatal("staged queue must be empty for the keepalive path to run")
	}

	drainMessageBuffers(t, dev)

	done := make(chan struct{})
	go func() {
		peer.SendKeepalive()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendKeepalive blocked on an exhausted buffer pool")
	}
}

// TestStagedSendKeepsHandshakeAttempts guards the other half of the same
// failure: expiredRetransmitHandshake only gives up, and only then flushes the
// staged queue, once handshakeAttempts reaches MaxTimerHandshakes. Traffic for a
// peer that cannot handshake must not keep resetting that counter.
func TestStagedSendKeepsHandshakeAttempts(t *testing.T) {
	dev, peer := newCappedDevice(t, 64)

	elem, ok := dev.TryNewOutboundElement()
	if !ok {
		t.Fatal("pool exhausted before the test started")
	}
	container, ok := dev.TryGetOutboundElementsContainer()
	if !ok {
		t.Fatal("pool exhausted before the test started")
	}
	container.elems = append(container.elems, elem)
	peer.queue.staged <- container

	peer.timers.handshakeAttempts.Store(3)
	peer.SendStagedPackets()

	if got := peer.timers.handshakeAttempts.Load(); got != 3 {
		t.Fatalf("handshakeAttempts = %d, want 3: the data path must not reset the give-up counter", got)
	}
}
