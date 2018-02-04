package main

import (
	"time"
)

type Timer struct {
	pending AtomicBool
	timer   *time.Timer
}

/* Starts the timer if not already pending
 */
func (t *Timer) Start(dur time.Duration) bool {
	set := t.pending.Swap(true)
	if !set {
		t.timer.Reset(dur)
		return true
	}
	return false
}

/* Stops the timer
 */
func (t *Timer) Stop() {
	set := t.pending.Swap(true)
	if set {
		t.timer.Stop()
		select {
		case <-t.timer.C:
		default:
		}
	}
	t.pending.Set(false)
}

func (t *Timer) Pending() bool {
	return t.pending.Get()
}

func (t *Timer) Reset(dur time.Duration) {
	t.pending.Set(false)
	t.Start(dur)
}

func (t *Timer) Wait() <-chan time.Time {
	return t.timer.C
}

func NewTimer() (t Timer) {
	t.pending.Set(false)
	t.timer = time.NewTimer(0)
	t.timer.Stop()
	select {
	case <-t.timer.C:
	default:
	}
	return
}
