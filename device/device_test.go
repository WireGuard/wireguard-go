/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func getFreePort(t *testing.T) string {
	l, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprintf("%d", l.LocalAddr().(*net.UDPAddr).Port)
}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(t *testing.T) (cfgs [2]*bufio.Reader) {
	const (
		cfg1 = `private_key=481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58
listen_port={{PORT1}}
replace_peers=true
public_key=f70dbb6b1b92a1dde1c783b297016af3f572fef13b0abb16a2623d89a58e9725
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.2/32
endpoint=127.0.0.1:{{PORT2}}`

		cfg2 = `private_key=98c7989b1661a0d64fd6af3502000f87716b7c4bbcf00d04fc6073aa7b539768
listen_port={{PORT2}}
replace_peers=true
public_key=49e80929259cebdda4f322d6d2b1a6fad819d603acd26fd5d845e7a123036427
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.1/32
endpoint=127.0.0.1:{{PORT1}}`
	)

	var port1, port2 string
	for port1 == port2 {
		port1 = getFreePort(t)
		port2 = getFreePort(t)
	}
	for i, cfg := range []string{cfg1, cfg2} {
		cfg = strings.ReplaceAll(cfg, "{{PORT1}}", port1)
		cfg = strings.ReplaceAll(cfg, "{{PORT2}}", port2)
		cfgs[i] = bufio.NewReader(strings.NewReader(cfg))
	}
	return
}

// genChannelTUNs creates a usable pair of ChannelTUNs for use in a test.
func genChannelTUNs(t *testing.T) (tun [2]*tuntest.ChannelTUN) {
	const maxAttempts = 10
NextAttempt:
	for i := 0; i < maxAttempts; i++ {
		cfg := genConfigs(t)
		// Bring up a ChannelTun for each config.
		for i := range tun {
			tun[i] = tuntest.NewChannelTUN()
			dev := NewDevice(tun[i].TUN(), NewLogger(LogLevelDebug, fmt.Sprintf("dev%d: ", i)))
			dev.Up()
			if err := dev.IpcSetOperation(cfg[i]); err != nil {
				// genConfigs attempted to pick ports that were free.
				// There's a tiny window between genConfigs closing the port
				// and us opening it, during which another process could
				// start using it. We probably just lost that race.
				// Try again from the beginning.
				// If there's something permanent wrong,
				// we'll see that when we run out of attempts.
				t.Logf("failed to configure device %d: %v", i, err)
				continue NextAttempt
			}
			// The device might still not be up, e.g. due to an error
			// in RoutineTUNEventReader's call to dev.Up that got swallowed.
			// Assume it's due to a transient error (port in use), and retry.
			if !dev.isUp.Get() {
				t.Logf("%v did not come up, trying again", dev)
				continue NextAttempt
			}
			// The device is up. Close it when the test completes.
			t.Cleanup(dev.Close)
		}
		return // success
	}

	t.Fatalf("genChannelTUNs: failed %d times", maxAttempts)
	return
}

func TestTwoDevicePing(t *testing.T) {
	tun := genChannelTUNs(t)

	t.Run("ping 1.0.0.1", func(t *testing.T) {
		msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
		tun[1].Outbound <- msg2to1
		select {
		case msgRecv := <-tun[0].Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-time.After(5 * time.Second):
			t.Error("ping did not transit")
		}
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		tun[0].Outbound <- msg1to2
		select {
		case msgRecv := <-tun[1].Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(5 * time.Second):
			t.Error("return ping did not transit")
		}
	})
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := newDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, logger)
	device.SetPrivateKey(sk)
	return device
}
