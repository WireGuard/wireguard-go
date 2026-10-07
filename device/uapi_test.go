/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestEndpointChangeDetection checks that only replacing an already-set
// endpoint with a different address counts as a change: a first-time
// assignment or a no-op reassignment must not, so a live session is never
// rekeyed unnecessarily.
func TestEndpointChangeDetection(t *testing.T) {
	dev, peer := newTestPeer(t)

	if changed := setEndpoint(t, dev, peer, "127.0.0.1:51820"); changed {
		t.Error("first-time endpoint assignment reported as a change")
	}
	if changed := setEndpoint(t, dev, peer, "127.0.0.1:51820"); changed {
		t.Error("reassigning the same endpoint reported as a change")
	}
	if changed := setEndpoint(t, dev, peer, "127.0.0.1:51821"); !changed {
		t.Error("changing the endpoint address was not reported as a change")
	}
}

func TestNeedsHandshake(t *testing.T) {
	_, peer := newTestPeer(t)

	if !peer.needsHandshake() {
		t.Error("peer without a keypair should need a handshake")
	}
}

func newTestPeer(t *testing.T) (*Device, *Peer) {
	t.Helper()

	var key NoisePrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	var peerKey NoisePrivateKey
	if _, err := rand.Read(peerKey[:]); err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	peerPub := peerKey.publicKey()

	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, "test: "))
	t.Cleanup(dev.Close)

	cfg := uapiCfg(
		"private_key", hex.EncodeToString(key[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(peerPub[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
	)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("configure device: %v", err)
	}

	peer := dev.LookupPeer(peerPub)
	if peer == nil {
		t.Fatal("configured peer not found")
	}
	return dev, peer
}

func setEndpoint(t *testing.T, dev *Device, peer *Peer, value string) bool {
	t.Helper()

	setPeer := &ipcSetPeer{Peer: peer}
	if err := dev.handlePeerLine(setPeer, "endpoint", value); err != nil {
		t.Fatalf("set endpoint %q: %v", value, err)
	}
	return setPeer.endpointChanged
}
