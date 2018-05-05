/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	PeerRoutineNumber = 4
	EventInterval     = 10 * time.Millisecond
)

type Peer struct {
	isRunning                   AtomicBool
	mutex                       sync.RWMutex
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	endpoint                    Endpoint
	persistentKeepaliveInterval uint16
	_                           uint32 // padding for alignment

	stats struct {
		txBytes           uint64 // bytes send to peer (endpoint)
		rxBytes           uint64 // bytes received from peer
		lastHandshakeNano int64  // nano seconds since epoch
	}

	time struct {
		mutex         sync.RWMutex
		lastSend      time.Time // last send message
		lastHandshake time.Time // last completed handshake
		nextKeepalive time.Time
	}

	event struct {
		dataSent                        *Event
		dataReceived                    *Event
		anyAuthenticatedPacketReceived  *Event
		anyAuthenticatedPacketTraversal *Event
		handshakeCompleted              *Event
		handshakePushDeadline           *Event
		handshakeBegin                  *Event
		ephemeralKeyCreated             *Event
		newKeyPair                      *Event
		flushNonceQueue                 *Event
	}

	timer struct {
		sendLastMinuteHandshake AtomicBool
	}

	queue struct {
		nonce    chan *QueueOutboundElement // nonce / pre-handshake queue
		outbound chan *QueueOutboundElement // sequential ordering of work
		inbound  chan *QueueInboundElement  // sequential ordering of work
	}

	routines struct {
		mutex    sync.Mutex     // held when stopping / starting routines
		starting sync.WaitGroup // routines pending start
		stopping sync.WaitGroup // routines pending stop
		stop     chan struct{}  // size 0, stop all go-routines in peer
	}

	mac CookieGenerator
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {

	if device.isClosed.Get() {
		return nil, errors.New("Device closed")
	}

	// lock resources

	device.state.mutex.Lock()
	defer device.state.mutex.Unlock()

	device.noise.mutex.RLock()
	defer device.noise.mutex.RUnlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// check if over limit

	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("Too many peers")
	}

	// create peer

	peer := new(Peer)
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	peer.mac.Init(pk)
	peer.device = device
	peer.isRunning.Set(false)

	// map public key

	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("Adding existing peer")
	}
	device.peers.keyMap[pk] = peer

	// pre-compute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic = device.noise.privateKey.sharedSecret(pk)
	handshake.mutex.Unlock()

	// reset endpoint

	peer.endpoint = nil

	// start peer

	if peer.device.isUp.Get() {
		peer.Start()
	}

	return peer, nil
}

func (peer *Peer) SendBuffer(buffer []byte) error {
	peer.device.net.mutex.RLock()
	defer peer.device.net.mutex.RUnlock()

	if peer.device.net.bind == nil {
		return errors.New("No bind")
	}

	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	if peer.endpoint == nil {
		return errors.New("No known endpoint for peer")
	}

	return peer.device.net.bind.Send(buffer, peer.endpoint)
}

/* Returns a short string identifier for logging
 */
func (peer *Peer) String() string {
	return fmt.Sprintf(
		"peer(%s)",
		base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:]),
	)
}

func (peer *Peer) Start() {

	// should never start a peer on a closed device

	if peer.device.isClosed.Get() {
		return
	}

	// prevent simultaneous start/stop operations

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Unlock()

	if peer.isRunning.Get() {
		return
	}

	device := peer.device
	device.log.Debug.Println(peer, ": Starting...")

	// reset routine state

	peer.routines.starting.Wait()
	peer.routines.stopping.Wait()
	peer.routines.stop = make(chan struct{})

	// prepare queues

	peer.queue.nonce = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.inbound = make(chan *QueueInboundElement, QueueInboundSize)

	// events

	peer.event.dataSent = newEvent(EventInterval)
	peer.event.dataReceived = newEvent(EventInterval)
	peer.event.anyAuthenticatedPacketReceived = newEvent(EventInterval)
	peer.event.anyAuthenticatedPacketTraversal = newEvent(EventInterval)
	peer.event.handshakeCompleted = newEvent(EventInterval)
	peer.event.handshakePushDeadline = newEvent(EventInterval)
	peer.event.handshakeBegin = newEvent(EventInterval)
	peer.event.ephemeralKeyCreated = newEvent(EventInterval)
	peer.event.newKeyPair = newEvent(EventInterval)
	peer.event.flushNonceQueue = newEvent(EventInterval)

	peer.isRunning.Set(true)

	// wait for routines to start

	peer.routines.starting.Add(PeerRoutineNumber)
	peer.routines.stopping.Add(PeerRoutineNumber)

	go peer.RoutineNonce()
	go peer.RoutineTimerHandler()
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	peer.routines.starting.Wait()
	peer.isRunning.Set(true)
}

func (peer *Peer) Stop() {

	// prevent simultaneous start/stop operations

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	device := peer.device
	device.log.Debug.Println(peer, ": Stopping...")

	// stop & wait for ongoing peer routines

	peer.routines.starting.Wait()
	close(peer.routines.stop)
	peer.routines.stopping.Wait()

	// close queues

	close(peer.queue.nonce)
	close(peer.queue.outbound)
	close(peer.queue.inbound)

	// clear key pairs

	kp := &peer.keyPairs
	kp.mutex.Lock()

	device.DeleteKeyPair(kp.previous)
	device.DeleteKeyPair(kp.current)
	device.DeleteKeyPair(kp.next)

	kp.previous = nil
	kp.current = nil
	kp.next = nil
	kp.mutex.Unlock()

	// clear handshake state

	hs := &peer.handshake
	hs.mutex.Lock()
	device.indices.Delete(hs.localIndex)
	hs.Clear()
	hs.mutex.Unlock()
}
