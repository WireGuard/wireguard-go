/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitPool(t *testing.T) {
	t.Skip("Currently disabled")
	var wg sync.WaitGroup
	trials := int32(100000)
	if raceEnabled {
		// This test can be very slow with -race.
		trials /= 10
	}
	workers := runtime.NumCPU() + 2
	if workers-4 <= 0 {
		t.Skip("Not enough cores")
	}
	p := NewWaitPool(uint32(workers-4), func() interface{} { return make([]byte, 16) })
	wg.Add(workers)
	max := uint32(0)
	updateMax := func() {
		count := atomic.LoadUint32(&p.count)
		if count > p.max {
			t.Errorf("count (%d) > max (%d)", count, p.max)
		}
		for {
			old := atomic.LoadUint32(&max)
			if count <= old {
				break
			}
			if atomic.CompareAndSwapUint32(&max, old, count) {
				break
			}
		}
	}
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for atomic.AddInt32(&trials, -1) > 0 {
				updateMax()
				x := p.Get()
				updateMax()
				time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)
				updateMax()
				p.Put(x)
				updateMax()
			}
		}()
	}
	wg.Wait()
	if max != p.max {
		t.Errorf("Actual maximum count (%d) != ideal maximum count (%d)", max, p.max)
	}
}

func BenchmarkWaitPool(b *testing.B) {
	var wg sync.WaitGroup
	trials := int32(b.N)
	workers := runtime.NumCPU() + 2
	if workers-4 <= 0 {
		b.Skip("Not enough cores")
	}
	p := NewWaitPool(uint32(workers-4), func() interface{} { return make([]byte, 16) })
	wg.Add(workers)
	b.ResetTimer()
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for atomic.AddInt32(&trials, -1) > 0 {
				x := p.Get()
				time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)
				p.Put(x)
			}
		}()
	}
	wg.Wait()
}
