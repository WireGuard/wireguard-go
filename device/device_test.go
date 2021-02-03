/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func getFreePort(tb testing.TB) string {
	l, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprintf("%d", l.LocalAddr().(*net.UDPAddr).Port)
}

// uapiCfg returns a string that contains cfg formatted use with IpcSet.
// cfg is a series of alternating key/value strings.
// uapiCfg exists because editors and humans like to insert
// whitespace into configs, which can cause failures, some of which are silent.
// For example, a leading blank newline causes the remainder
// of the config to be silently ignored.
func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(tb testing.TB) (cfgs [2]string) {
	var port1, port2 string
	for port1 == port2 {
		port1 = getFreePort(tb)
		port2 = getFreePort(tb)
	}

	cfgs[0] = uapiCfg(
		"private_key", "481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58",
		"listen_port", port1,
		"replace_peers", "true",
		"public_key", "f70dbb6b1b92a1dde1c783b297016af3f572fef13b0abb16a2623d89a58e9725",
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
		"endpoint", "127.0.0.1:"+port2,
	)
	cfgs[1] = uapiCfg(
		"private_key", "98c7989b1661a0d64fd6af3502000f87716b7c4bbcf00d04fc6073aa7b539768",
		"listen_port", port2,
		"replace_peers", "true",
		"public_key", "49e80929259cebdda4f322d6d2b1a6fad819d603acd26fd5d845e7a123036427",
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.1/32",
		"endpoint", "127.0.0.1:"+port1,
	)
	return
}

// A testPair is a pair of testPeers.
type testPair [2]testPeer

// A testPeer is a peer used for testing.
type testPeer struct {
	tun *tuntest.ChannelTUN
	dev *Device
	ip  net.IP
}

type SendDirection bool

const (
	Ping SendDirection = true
	Pong SendDirection = false
)

func (pair *testPair) Send(tb testing.TB, ping SendDirection, done chan struct{}) {
	tb.Helper()
	p0, p1 := pair[0], pair[1]
	if !ping {
		// pong is the new ping
		p0, p1 = p1, p0
	}
	msg := tuntest.Ping(p0.ip, p1.ip)
	p1.tun.Outbound <- msg
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var err error
	select {
	case msgRecv := <-p0.tun.Inbound:
		if !bytes.Equal(msg, msgRecv) {
			err = errors.New("ping did not transit correctly")
		}
	case <-timer.C:
		err = errors.New("ping did not transit")
	case <-done:
	}
	if err != nil {
		// The error may have occurred because the test is done.
		select {
		case <-done:
			return
		default:
		}
		// Real error.
		tb.Error(err)
	}
}

// genTestPair creates a testPair.
func genTestPair(tb testing.TB) (pair testPair) {
	const maxAttempts = 10
NextAttempt:
	for i := 0; i < maxAttempts; i++ {
		cfg := genConfigs(tb)
		// Bring up a ChannelTun for each config.
		for i := range pair {
			p := &pair[i]
			p.tun = tuntest.NewChannelTUN()
			if i == 0 {
				p.ip = net.ParseIP("1.0.0.1")
			} else {
				p.ip = net.ParseIP("1.0.0.2")
			}
			level := LogLevelVerbose
			if _, ok := tb.(*testing.B); ok && !testing.Verbose() {
				level = LogLevelError
			}
			p.dev = NewDevice(p.tun.TUN(), NewLogger(level, fmt.Sprintf("dev%d: ", i)))
			p.dev.Up()
			if err := p.dev.IpcSet(cfg[i]); err != nil {
				// genConfigs attempted to pick ports that were free.
				// There's a tiny window between genConfigs closing the port
				// and us opening it, during which another process could
				// start using it. We probably just lost that race.
				// Try again from the beginning.
				// If there's something permanent wrong,
				// we'll see that when we run out of attempts.
				tb.Logf("failed to configure device %d: %v", i, err)
				p.dev.Close()
				continue NextAttempt
			}
			// The device might still not be up, e.g. due to an error
			// in RoutineTUNEventReader's call to dev.Up that got swallowed.
			// Assume it's due to a transient error (port in use), and retry.
			if !p.dev.isUp.Get() {
				tb.Logf("device %d did not come up, trying again", i)
				p.dev.Close()
				continue NextAttempt
			}
			// The device is up. Close it when the test completes.
			tb.Cleanup(p.dev.Close)
		}
		return // success
	}

	tb.Fatalf("genChannelTUNs: failed %d times", maxAttempts)
	return
}

func TestTwoDevicePing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t)
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

func TestUpDown(t *testing.T) {
	goroutineLeakCheck(t)
	const itrials = 200
	const otrials = 10

	for n := 0; n < otrials; n++ {
		pair := genTestPair(t)
		for i := range pair {
			for k := range pair[i].dev.peers.keyMap {
				pair[i].dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=1\n", hex.EncodeToString(k[:])))
			}
		}
		var wg sync.WaitGroup
		wg.Add(len(pair))
		for i := range pair {
			go func(d *Device) {
				defer wg.Done()
				for i := 0; i < itrials; i++ {
					d.Up()
					time.Sleep(time.Duration(rand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
					d.Down()
					time.Sleep(time.Duration(rand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
				}
			}(pair[i].dev)
		}
		wg.Wait()
		for i := range pair {
			pair[i].dev.Up()
			pair[i].dev.Close()
		}
	}
}

// TestConcurrencySafety does other things concurrently with tunnel use.
// It is intended to be used with the race detector to catch data races.
func TestConcurrencySafety(t *testing.T) {
	pair := genTestPair(t)
	done := make(chan struct{})

	const warmupIters = 10
	var warmup sync.WaitGroup
	warmup.Add(warmupIters)
	go func() {
		// Send data continuously back and forth until we're done.
		// Note that we may continue to attempt to send data
		// even after done is closed.
		i := warmupIters
		for ping := Ping; ; ping = !ping {
			pair.Send(t, ping, done)
			select {
			case <-done:
				return
			default:
			}
			if i > 0 {
				warmup.Done()
				i--
			}
		}
	}()
	warmup.Wait()

	applyCfg := func(cfg string) {
		err := pair[0].dev.IpcSet(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Change persistent_keepalive_interval concurrently with tunnel use.
	t.Run("persistentKeepaliveInterval", func(t *testing.T) {
		cfg := uapiCfg(
			"public_key", "f70dbb6b1b92a1dde1c783b297016af3f572fef13b0abb16a2623d89a58e9725",
			"persistent_keepalive_interval", "1",
		)
		for i := 0; i < 1000; i++ {
			applyCfg(cfg)
		}
	})

	// Change private keys concurrently with tunnel use.
	t.Run("privateKey", func(t *testing.T) {
		bad := uapiCfg("private_key", "7777777777777777777777777777777777777777777777777777777777777777")
		good := uapiCfg("private_key", "481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58")
		// Set iters to a large number like 1000 to flush out data races quickly.
		// Don't leave it large. That can cause logical races
		// in which the handshake is interleaved with key changes
		// such that the private key appears to be unchanging but
		// other state gets reset, which can cause handshake failures like
		// "Received packet with invalid mac1".
		const iters = 1
		for i := 0; i < iters; i++ {
			applyCfg(bad)
			applyCfg(good)
		}
	})

	close(done)
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

func BenchmarkLatency(b *testing.B) {
	pair := genTestPair(b)

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair.Send(b, Ping, nil)
		pair.Send(b, Pong, nil)
	}
}

func BenchmarkThroughput(b *testing.B) {
	pair := genTestPair(b)

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	// Measure how long it takes to receive b.N packets,
	// starting when we receive the first packet.
	var recv uint64
	var elapsed time.Duration
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var start time.Time
		for {
			<-pair[0].tun.Inbound
			new := atomic.AddUint64(&recv, 1)
			if new == 1 {
				start = time.Now()
			}
			// Careful! Don't change this to else if; b.N can be equal to 1.
			if new == uint64(b.N) {
				elapsed = time.Since(start)
				return
			}
		}
	}()

	// Send packets as fast as we can until we've received enough.
	ping := tuntest.Ping(pair[0].ip, pair[1].ip)
	pingc := pair[1].tun.Outbound
	var sent uint64
	for atomic.LoadUint64(&recv) != uint64(b.N) {
		sent++
		pingc <- ping
	}
	wg.Wait()

	b.ReportMetric(float64(elapsed)/float64(b.N), "ns/op")
	b.ReportMetric(1-float64(b.N)/float64(sent), "packet-loss")
}

func BenchmarkUAPIGet(b *testing.B) {
	pair := genTestPair(b)
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair[0].dev.IpcGetOperation(ioutil.Discard)
	}
}

func goroutineLeakCheck(t *testing.T) {
	goroutines := func() (int, []byte) {
		p := pprof.Lookup("goroutine")
		b := new(bytes.Buffer)
		p.WriteTo(b, 1)
		return p.Count(), b.Bytes()
	}

	startGoroutines, startStacks := goroutines()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		// Give goroutines time to exit, if they need it.
		for i := 0; i < 10000; i++ {
			if runtime.NumGoroutine() <= startGoroutines {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endGoroutines, endStacks := goroutines()
		t.Logf("starting stacks:\n%s\n", startStacks)
		t.Logf("ending stacks:\n%s\n", endStacks)
		t.Fatalf("expected %d goroutines, got %d, leak?", startGoroutines, endGoroutines)
	})
}
