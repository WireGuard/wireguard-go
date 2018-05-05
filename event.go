package main

import (
	"sync/atomic"
	"time"
)

type Event struct {
	guard    int32
	next     time.Time
	interval time.Duration
	C        chan struct{}
}

func newEvent(interval time.Duration) *Event {
	return &Event{
		guard:    0,
		next:     time.Now(),
		interval: interval,
		C:        make(chan struct{}, 1),
	}
}

func (e *Event) Clear() {
	select {
	case <-e.C:
	default:
	}
}

func (e *Event) Fire() {
	if e == nil || atomic.SwapInt32(&e.guard, 1) != 0 {
		return
	}
	now := time.Now()
	if e.next.After(now) {
		select {
		case e.C <- struct{}{}:
		default:
		}
		e.next = now.Add(e.interval)
	}
	atomic.StoreInt32(&e.guard, 0)
}
