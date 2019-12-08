/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package ratelimiter

import (
	"net"
	"testing"
	"time"
)

type result struct {
	allowed bool
	text    string
	wait    time.Duration
}

func TestRatelimiter(t *testing.T) {
	var rate Ratelimiter
	var expectedResults []result

	nano := func(nano int64) time.Duration {
		return time.Nanosecond * time.Duration(nano)
	}

	add := func(res result) {
		expectedResults = append(
			expectedResults,
			res,
		)
	}

	for i := 0; i < packetsBurstable; i++ {
		add(result{
			allowed: true,
			text:    "initial burst",
		})
	}

	add(result{
		allowed: false,
		text:    "after burst",
	})

	add(result{
		allowed: true,
		wait:    nano(time.Second.Nanoseconds() / packetsPerSecond),
		text:    "filling tokens for single packet",
	})

	add(result{
		allowed: false,
		text:    "not having refilled enough",
	})

	add(result{
		allowed: true,
		wait:    2 * (nano(time.Second.Nanoseconds() / packetsPerSecond)),
		text:    "filling tokens for two packet burst",
	})

	add(result{
		allowed: true,
		text:    "second packet in 2 packet burst",
	})

	add(result{
		allowed: false,
		text:    "packet following 2 packet burst",
	})

	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("172.167.2.3"),
		net.ParseIP("97.231.252.215"),
		net.ParseIP("248.97.91.167"),
		net.ParseIP("188.208.233.47"),
		net.ParseIP("104.2.183.179"),
		net.ParseIP("72.129.46.120"),
		net.ParseIP("2001:0db8:0a0b:12f0:0000:0000:0000:0001"),
		net.ParseIP("f5c2:818f:c052:655a:9860:b136:6894:25f0"),
		net.ParseIP("b2d7:15ab:48a7:b07c:a541:f144:a9fe:54fc"),
		net.ParseIP("a47b:786e:1671:a22b:d6f9:4ab0:abc7:c918"),
		net.ParseIP("ea1e:d155:7f7a:98fb:2bf5:9483:80f6:5445"),
		net.ParseIP("3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4"),
	}

	now := time.Now()
	rate.timeNow = func() time.Time {
		return now
	}
	defer func() {
		// Lock to avoid data race with cleanup goroutine from Init.
		rate.mu.Lock()
		defer rate.mu.Unlock()

		rate.timeNow = time.Now
	}()
	timeSleep := func(d time.Duration) {
		now = now.Add(d + 1)
		rate.cleanup()
	}

	rate.Init()
	defer rate.Close()

	for i, res := range expectedResults {
		timeSleep(res.wait)
		for _, ip := range ips {
			allowed := rate.Allow(ip)
			if allowed != res.allowed {
				t.Fatalf("%d: %s: rate.Allow(%q)=%v, want %v", i, res.text, ip, allowed, res.allowed)
			}
		}
	}
}
