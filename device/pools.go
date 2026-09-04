/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
)

type WaitPool struct {
	pool    sync.Pool
	cond    sync.Cond
	lock    sync.Mutex
	count   uint32 // Get calls not yet Put back
	max     uint32
	tracked bool // true if max was non-zero at construction; enables SetMax
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max, tracked: max != 0}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.tracked {
		p.lock.Lock()
		for p.max != 0 && p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

// TryGet is Get without the wait: on a tracked pool that is at capacity it
// reports false instead of blocking. Callers that run inside a WireGuard timer
// callback must use this - a callback holds the timer's runningLock, and
// Timer.DelSync waits on that lock, so a callback parked in Get makes peer
// removal and device close impossible.
func (p *WaitPool) TryGet() (any, bool) {
	if p.tracked {
		p.lock.Lock()
		if p.max != 0 && p.count >= p.max {
			p.lock.Unlock()
			return nil, false
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get(), true
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if !p.tracked {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}

// SetMax updates the pool cap. Takes effect immediately; waiters are
// broadcast so they re-check against the new value. Has no effect if the
// pool was constructed with max == 0 (unbounded, fast-path Get/Put).
func (p *WaitPool) SetMax(n uint32) {
	if !p.tracked {
		return
	}
	p.lock.Lock()
	p.max = n
	p.cond.Broadcast()
	p.lock.Unlock()
}

func (device *Device) PopulatePools() {
	device.pool.inboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	device.pool.outboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	device.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

func (device *Device) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := device.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

func (device *Device) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.inboundElementsContainer.Put(c)
}

func (device *Device) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := device.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

// TryGetOutboundElementsContainer is GetOutboundElementsContainer without the wait.
func (device *Device) TryGetOutboundElementsContainer() (*QueueOutboundElementsContainer, bool) {
	v, ok := device.pool.outboundElementsContainer.TryGet()
	if !ok {
		return nil, false
	}
	c := v.(*QueueOutboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c, true
}

func (device *Device) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.outboundElementsContainer.Put(c)
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

// TryGetMessageBuffer is GetMessageBuffer without the wait.
func (device *Device) TryGetMessageBuffer() (*[MaxMessageSize]byte, bool) {
	v, ok := device.pool.messageBuffers.TryGet()
	if !ok {
		return nil, false
	}
	return v.(*[MaxMessageSize]byte), true
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

// TryGetOutboundElement is GetOutboundElement without the wait.
func (device *Device) TryGetOutboundElement() (*QueueOutboundElement, bool) {
	v, ok := device.pool.outboundElements.TryGet()
	if !ok {
		return nil, false
	}
	return v.(*QueueOutboundElement), true
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
