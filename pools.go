/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import "sync"

var preallocatedBuffers = 0

func (device *Device) PopulatePools() {
	if preallocatedBuffers == 0 {
		device.pool.messageBufferPool = &sync.Pool{
			New: func() interface{} {
				return new([MaxMessageSize]byte)
			},
		}
		device.pool.inboundElementPool = &sync.Pool{
			New: func() interface{} {
				return new(QueueInboundElement)
			},
		}
		device.pool.outboundElementPool = &sync.Pool{
			New: func() interface{} {
				return new(QueueOutboundElement)
			},
		}
	} else {
		device.pool.messageBufferReuseChan = make(chan *[MaxMessageSize]byte, preallocatedBuffers)
		for i := 0; i < preallocatedBuffers; i += 1 {
			device.pool.messageBufferReuseChan <- new([MaxMessageSize]byte)
		}
		device.pool.inboundElementReuseChan = make(chan *QueueInboundElement, preallocatedBuffers)
		for i := 0; i < preallocatedBuffers; i += 1 {
			device.pool.inboundElementReuseChan <- new(QueueInboundElement)
		}
		device.pool.outboundElementReuseChan = make(chan *QueueOutboundElement, preallocatedBuffers)
		for i := 0; i < preallocatedBuffers; i += 1 {
			device.pool.outboundElementReuseChan <- new(QueueOutboundElement)
		}
	}
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	if preallocatedBuffers == 0 {
		return device.pool.messageBufferPool.Get().(*[MaxMessageSize]byte)
	} else {
		return <-device.pool.messageBufferReuseChan
	}
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	if preallocatedBuffers == 0 {
		device.pool.messageBufferPool.Put(msg)
	} else {
		device.pool.messageBufferReuseChan <- msg
	}
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	if preallocatedBuffers == 0 {
		return device.pool.inboundElementPool.Get().(*QueueInboundElement)
	} else {
		return <-device.pool.inboundElementReuseChan
	}
}

func (device *Device) PutInboundElement(msg *QueueInboundElement) {
	if preallocatedBuffers == 0 {
		device.pool.inboundElementPool.Put(msg)
	} else {
		device.pool.inboundElementReuseChan <- msg
	}
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	if preallocatedBuffers == 0 {
		return device.pool.outboundElementPool.Get().(*QueueOutboundElement)
	} else {
		return <-device.pool.outboundElementReuseChan
	}
}

func (device *Device) PutOutboundElement(msg *QueueOutboundElement) {
	if preallocatedBuffers == 0 {
		device.pool.outboundElementPool.Put(msg)
	} else {
		device.pool.outboundElementReuseChan <- msg
	}
}
