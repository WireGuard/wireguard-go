/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"net/netip"
	"sync"
	"testing"
)

func newTestTUN(t *testing.T) *netTun {
	t.Helper()

	dev, _, err := CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.1.1")},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1280,
	)
	if err != nil {
		t.Fatalf("create net TUN: %v", err)
	}

	tun, ok := dev.(*netTun)
	if !ok {
		t.Fatalf("CreateNetTUN returned %T, want *netTun", dev)
	}
	return tun
}

// TestNetTunCloseTwice covers the sequential case: Close must tolerate being
// called again.
//
// Nothing above this layer can guarantee a single call. Device.Close closes the
// device it was handed, and it is reached both from an ordinary teardown and
// from RoutineReadFromTUN, while callers embedding the device keep their own
// references. Without the guard the second call closes an already closed
// channel and panics the process.
func TestNetTunCloseTwice(t *testing.T) {
	tun := newTestTUN(t)

	if err := tun.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// TestNetTunCloseConcurrent covers the case actually seen in the field: two
// goroutines closing the same device at once, which is what a teardown racing
// RoutineReadFromTUN looks like.
func TestNetTunCloseConcurrent(t *testing.T) {
	for i := 0; i < 50; i++ {
		tun := newTestTUN(t)

		const closers = 8
		var start sync.WaitGroup
		var done sync.WaitGroup
		start.Add(1)
		done.Add(closers)

		for c := 0; c < closers; c++ {
			go func() {
				defer done.Done()
				start.Wait()
				_ = tun.Close()
			}()
		}

		start.Done()
		done.Wait()
	}
}

// TestNetTunEventsClosedOnce checks that the guard still closes the channels
// rather than skipping the teardown: the events channel must be closed after
// Close returns, so readers observing it are released.
func TestNetTunEventsClosedOnce(t *testing.T) {
	tun := newTestTUN(t)

	events := tun.Events()
	if err := tun.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Drain whatever was already queued; the channel must then report closed
	// rather than blocking, otherwise readers are never released.
	for i := 0; i < 16; i++ {
		if _, open := <-events; !open {
			return
		}
	}
	t.Fatal("events channel never reported closed after Close")
}
