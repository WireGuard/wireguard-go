/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
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
	PeerRoutineNumber = 3
)

type Peer struct {
	isRunning                   AtomicBool
	mutex                       sync.RWMutex // Mostly protects endpoint, but is generally taken whenever we modify peer
	keypairs                    Keypairs
	handshake                   Handshake
	device                      *Device
	endpoint                    Endpoint
	persistentKeepaliveInterval uint16

	// This must be 64-bit aligned, so make sure the above members come out to even alignment and pad accordingly
	stats struct {
		txBytes           uint64 // bytes send to peer (endpoint)
		rxBytes           uint64 // bytes received from peer
		lastHandshakeNano int64  // nano seconds since epoch
	}

	timers struct {
		retransmitHandshake     *Timer
		sendKeepalive           *Timer
		newHandshake            *Timer
		zeroKeyMaterial         *Timer
		persistentKeepalive     *Timer
		handshakeAttempts       uint32
		needAnotherKeepalive    AtomicBool
		sentLastMinuteHandshake AtomicBool
	}

	signals struct {
		newKeypairArrived chan struct{}
		flushNonceQueue   chan struct{}
	}

	queue struct {
		nonce                           chan *QueueOutboundElement // nonce / pre-handshake queue
		outbound                        chan *QueueOutboundElement // sequential ordering of work
		inbound                         chan *QueueInboundElement  // sequential ordering of work
		packetInNonceQueueIsAwaitingKey AtomicBool
	}

	routines struct {
		mutex    sync.Mutex     // held when stopping / starting routines
		starting sync.WaitGroup // routines pending start
		stopping sync.WaitGroup // routines pending stop
		stop     chan struct{}  // size 0, stop all go routines in peer
	}

	cookieGenerator CookieGenerator
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {

	if device.isClosed.Get() {
		return nil, errors.New("device closed")
	}

	// lock resources

	device.staticIdentity.mutex.RLock()
	defer device.staticIdentity.mutex.RUnlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// check if over limit

	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer

	peer := new(Peer)
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.isRunning.Set(false)

	// map public key

	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}
	device.peers.keyMap[pk] = peer

	// pre-compute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic = device.staticIdentity.privateKey.sharedSecret(pk)
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
		return errors.New("no bind")
	}

	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	if peer.endpoint == nil {
		return errors.New("no known endpoint for peer")
	}

	return peer.device.net.bind.Send(buffer, peer.endpoint)
}

func (peer *Peer) String() string {
	base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	abbreviatedKey := "invalid"
	if len(base64Key) == 44 {
		abbreviatedKey = base64Key[0:4] + "…" + base64Key[39:43]
	}
	return fmt.Sprintf("peer(%s)", abbreviatedKey)
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
	device.log.Debug.Println(peer, "- Starting...")

	// reset routine state

	peer.routines.starting.Wait()
	peer.routines.stopping.Wait()
	peer.routines.stop = make(chan struct{})
	peer.routines.starting.Add(PeerRoutineNumber)
	peer.routines.stopping.Add(PeerRoutineNumber)

	// prepare queues

	peer.queue.nonce = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.inbound = make(chan *QueueInboundElement, QueueInboundSize)

	peer.timersInit()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.signals.newKeypairArrived = make(chan struct{}, 1)
	peer.signals.flushNonceQueue = make(chan struct{}, 1)

	// wait for routines to start

	go peer.RoutineNonce()
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	peer.routines.starting.Wait()
	peer.isRunning.Set(true)
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.mutex.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next)
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next = nil
	keypairs.mutex.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushNonceQueue()
}

func (peer *Peer) Stop() {

	// prevent simultaneous start/stop operations

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.routines.starting.Wait()

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Unlock()

	peer.device.log.Debug.Println(peer, "- Stopping...")

	peer.timersStop()

	// stop & wait for ongoing peer routines

	close(peer.routines.stop)
	peer.routines.stopping.Wait()

	// close queues

	close(peer.queue.nonce)
	close(peer.queue.outbound)
	close(peer.queue.inbound)

	peer.ZeroAndFlushAll()
}

var roamingDisabled bool

func (peer *Peer) SetEndpointFromPacket(endpoint Endpoint) {
	if roamingDisabled {
		return
	}
	peer.mutex.Lock()
	peer.endpoint = endpoint
	peer.mutex.Unlock()
}
