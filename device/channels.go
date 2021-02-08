/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import "sync"

// An outboundQueue is a channel of QueueOutboundElements awaiting encryption.
// An outboundQueue is ref-counted using its wg field.
// An outboundQueue created with newOutboundQueue has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.
type outboundQueue struct {
	c  chan *QueueOutboundElement
	wg sync.WaitGroup
}

func newOutboundQueue() *outboundQueue {
	q := &outboundQueue{
		c: make(chan *QueueOutboundElement, QueueOutboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A inboundQueue is similar to an outboundQueue; see those docs.
type inboundQueue struct {
	c  chan *QueueInboundElement
	wg sync.WaitGroup
}

func newInboundQueue() *inboundQueue {
	q := &inboundQueue{
		c: make(chan *QueueInboundElement, QueueInboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A handshakeQueue is similar to an outboundQueue; see those docs.
type handshakeQueue struct {
	c  chan QueueHandshakeElement
	wg sync.WaitGroup
}

func newHandshakeQueue() *handshakeQueue {
	q := &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}
