/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"sync"
	"time"
)

type Timer struct {
	mutex   sync.Mutex
	pending bool
	timer   *time.Timer
}

/* Starts the timer if not already pending
 */
func (t *Timer) Start(dur time.Duration) bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	started := !t.pending
	if started {
		t.timer.Reset(dur)
	}
	return started
}

func (t *Timer) Stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.timer.Stop()
	select {
	case <-t.timer.C:
	default:
	}
	t.pending = false
}

func (t *Timer) Pending() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.pending
}

func (t *Timer) Reset(dur time.Duration) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.timer.Reset(dur)
}

func (t *Timer) Wait() <-chan time.Time {
	return t.timer.C
}

func NewTimer() (t Timer) {
	t.pending = false
	t.timer = time.NewTimer(time.Hour)
	t.timer.Stop()
	select {
	case <-t.timer.C:
	default:
	}
	return
}
