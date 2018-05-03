/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package ratelimiter

import (
	"net"
	"sync"
	"time"
)

const (
	packetsPerSecond   = 20
	packetsBurstable   = 5
	garbageCollectTime = time.Second
	packetCost         = 1000000000 / packetsPerSecond
	maxTokens          = packetCost * packetsBurstable
)

type RatelimiterEntry struct {
	mutex    sync.Mutex
	lastTime time.Time
	tokens   int64
}

type Ratelimiter struct {
	mutex     sync.RWMutex
	stop      chan struct{}
	tableIPv4 map[[net.IPv4len]byte]*RatelimiterEntry
	tableIPv6 map[[net.IPv6len]byte]*RatelimiterEntry
}

func (rate *Ratelimiter) Close() {
	rate.mutex.Lock()
	defer rate.mutex.Unlock()

	if rate.stop != nil {
		close(rate.stop)
	}
}

func (rate *Ratelimiter) Init() {
	rate.mutex.Lock()
	defer rate.mutex.Unlock()

	// stop any ongoing garbage collection routine

	if rate.stop != nil {
		close(rate.stop)
	}

	rate.stop = make(chan struct{})
	rate.tableIPv4 = make(map[[net.IPv4len]byte]*RatelimiterEntry)
	rate.tableIPv6 = make(map[[net.IPv6len]byte]*RatelimiterEntry)

	// start garbage collection routine

	go func() {
		timer := time.NewTimer(time.Second)
		for {
			select {
			case <-rate.stop:
				return
			case <-timer.C:
				func() {
					rate.mutex.Lock()
					defer rate.mutex.Unlock()

					for key, entry := range rate.tableIPv4 {
						entry.mutex.Lock()
						if time.Now().Sub(entry.lastTime) > garbageCollectTime {
							delete(rate.tableIPv4, key)
						}
						entry.mutex.Unlock()
					}

					for key, entry := range rate.tableIPv6 {
						entry.mutex.Lock()
						if time.Now().Sub(entry.lastTime) > garbageCollectTime {
							delete(rate.tableIPv6, key)
						}
						entry.mutex.Unlock()
					}
				}()
				timer.Reset(time.Second)
			}
		}
	}()
}

func (rate *Ratelimiter) Allow(ip net.IP) bool {
	var entry *RatelimiterEntry
	var KeyIPv4 [net.IPv4len]byte
	var KeyIPv6 [net.IPv6len]byte

	// lookup entry

	IPv4 := ip.To4()
	IPv6 := ip.To16()

	rate.mutex.RLock()

	if IPv4 != nil {
		copy(KeyIPv4[:], IPv4)
		entry = rate.tableIPv4[KeyIPv4]
	} else {
		copy(KeyIPv6[:], IPv6)
		entry = rate.tableIPv6[KeyIPv6]
	}

	rate.mutex.RUnlock()

	// make new entry if not found

	if entry == nil {
		rate.mutex.Lock()
		entry = new(RatelimiterEntry)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = time.Now()
		if IPv4 != nil {
			rate.tableIPv4[KeyIPv4] = entry
		} else {
			rate.tableIPv6[KeyIPv6] = entry
		}
		rate.mutex.Unlock()
		return true
	}

	// add tokens to entry

	entry.mutex.Lock()
	now := time.Now()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}

	// subtract cost of packet

	if entry.tokens > packetCost {
		entry.tokens -= packetCost
		entry.mutex.Unlock()
		return true
	}
	entry.mutex.Unlock()
	return false
}
