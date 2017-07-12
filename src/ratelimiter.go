package main

/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

/* This file contains a port of the ratelimited from the linux kernel version
 */

import (
	"net"
	"sync"
	"time"
)

const (
	RatelimiterPacketsPerSecond   = 20
	RatelimiterPacketsBurstable   = 5
	RatelimiterGarbageCollectTime = time.Second
	RatelimiterPacketCost         = 1000000000 / RatelimiterPacketsPerSecond
	RatelimiterMaxTokens          = RatelimiterPacketCost * RatelimiterPacketsBurstable
)

type RatelimiterEntry struct {
	mutex    sync.Mutex
	lastTime time.Time
	tokens   int64
}

type Ratelimiter struct {
	mutex              sync.RWMutex
	lastGarbageCollect time.Time
	tableIPv4          map[[net.IPv4len]byte]*RatelimiterEntry
	tableIPv6          map[[net.IPv6len]byte]*RatelimiterEntry
}

func (rate *Ratelimiter) Init() {
	rate.mutex.Lock()
	defer rate.mutex.Unlock()
	rate.tableIPv4 = make(map[[net.IPv4len]byte]*RatelimiterEntry)
	rate.tableIPv6 = make(map[[net.IPv6len]byte]*RatelimiterEntry)
	rate.lastGarbageCollect = time.Now()
}

func (rate *Ratelimiter) GarbageCollectEntries() {
	rate.mutex.Lock()

	// remove unused IPv4 entries

	for key, entry := range rate.tableIPv4 {
		entry.mutex.Lock()
		if time.Now().Sub(entry.lastTime) > RatelimiterGarbageCollectTime {
			delete(rate.tableIPv4, key)
		}
		entry.mutex.Unlock()
	}

	// remove unused IPv6 entries

	for key, entry := range rate.tableIPv6 {
		entry.mutex.Lock()
		if time.Now().Sub(entry.lastTime) > RatelimiterGarbageCollectTime {
			delete(rate.tableIPv6, key)
		}
		entry.mutex.Unlock()
	}

	rate.mutex.Unlock()
}

func (rate *Ratelimiter) RoutineGarbageCollector(stop chan struct{}) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			rate.GarbageCollectEntries()
			timer.Reset(time.Second)
		}
	}
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
		entry.tokens = RatelimiterMaxTokens - RatelimiterPacketCost
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
	if entry.tokens > RatelimiterMaxTokens {
		entry.tokens = RatelimiterMaxTokens
	}

	// subtract cost of packet

	if entry.tokens > RatelimiterPacketCost {
		entry.tokens -= RatelimiterPacketCost
		entry.mutex.Unlock()
		return true
	}
	entry.mutex.Unlock()
	return false
}
