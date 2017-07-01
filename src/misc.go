package main

import (
	"time"
)

func min(a uint, b uint) uint {
	if a > b {
		return b
	}
	return a
}

func sendSignal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func stoppedTimer() *time.Timer {
	timer := time.NewTimer(time.Hour)
	stopTimer(timer)
	return timer
}
