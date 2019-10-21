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

type RatelimiterResult struct {
	allowed bool
	text    string
	wait    time.Duration
}

func TestRatelimiter(t *testing.T) {

	var ratelimiter Ratelimiter
	var expectedResults []RatelimiterResult

	Nano := func(nano int64) time.Duration {
		return time.Nanosecond * time.Duration(nano)
	}

	Add := func(res RatelimiterResult) {
		expectedResults = append(
			expectedResults,
			res,
		)
	}

	for i := 0; i < packetsBurstable; i++ {
		Add(RatelimiterResult{
			allowed: true,
			text:    "initial burst",
		})
	}

	Add(RatelimiterResult{
		allowed: false,
		text:    "after burst",
	})

	Add(RatelimiterResult{
		allowed: true,
		wait:    Nano(time.Second.Nanoseconds() / packetsPerSecond),
		text:    "filling tokens for single packet",
	})

	Add(RatelimiterResult{
		allowed: false,
		text:    "not having refilled enough",
	})

	Add(RatelimiterResult{
		allowed: true,
		wait:    2 * (Nano(time.Second.Nanoseconds() / packetsPerSecond)),
		text:    "filling tokens for two packet burst",
	})

	Add(RatelimiterResult{
		allowed: true,
		text:    "second packet in 2 packet burst",
	})

	Add(RatelimiterResult{
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

	ratelimiter.Init()

	for i, res := range expectedResults {
		time.Sleep(res.wait)
		for _, ip := range ips {
			allowed := ratelimiter.Allow(ip)
			if allowed != res.allowed {
				t.Fatal("Test failed for", ip.String(), ", on:", i, "(", res.text, ")", "expected:", res.allowed, "got:", allowed)
			}
		}
	}
}
