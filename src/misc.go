package main

import (
	"time"
)

/* We use int32 as atomic bools
 * (since booleans are not natively supported by sync/atomic)
 */
const (
	AtomicFalse = iota
	AtomicTrue
)

func min(a uint, b uint) uint {
	if a > b {
		return b
	}
	return a
}

func minUint64(a uint64, b uint64) uint64 {
	if a > b {
		return b
	}
	return a
}

func signalSend(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func signalClear(c chan struct{}) {
	select {
	case <-c:
	default:
	}
}

func timerStop(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func NewStoppedTimer() *time.Timer {
	timer := time.NewTimer(time.Hour)
	timerStop(timer)
	return timer
}
