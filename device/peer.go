/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	PeerRoutineNumber = 3
)

type Peer struct {
	isRunning                   AtomicBool
	sync.RWMutex                // Mostly protects endpoint, but is generally taken whenever we modify peer
	keypairs                    Keypairs
	handshake                   Handshake
	device                      *Device
	endpoint                    conn.Endpoint
	persistentKeepaliveInterval uint16
	disableRoaming              bool

	// These fields are accessed with atomic operations, which must be
	// 64-bit aligned even on 32-bit platforms. Go guarantees that an
	// allocated struct will be 64-bit aligned. So we place
	// atomically-accessed fields up front, so that they can share in
	// this alignment before smaller fields throw it off.
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
		sync.RWMutex
		nonce                           chan *QueueOutboundElement // nonce / pre-handshake queue
		outbound                        chan *QueueOutboundElement // sequential ordering of work
		inbound                         chan *QueueInboundElement  // sequential ordering of work
		packetInNonceQueueIsAwaitingKey AtomicBool
	}

	routines struct {
		sync.Mutex                // held when stopping / starting routines
		starting   sync.WaitGroup // routines pending start
		stopping   sync.WaitGroup // routines pending stop
		stop       chan struct{}  // size 0, stop all go routines in peer
	}

	cookieGenerator CookieGenerator
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if device.isClosed.Get() {
		return nil, errors.New("device closed")
	}

	// lock resources

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	// check if over limit

	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer

	peer := new(Peer)
	peer.Lock()
	defer peer.Unlock()

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.isRunning.Set(false)

	// map public key

	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// pre-compute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint

	peer.endpoint = nil

	// add

	device.peers.keyMap[pk] = peer

	// start peer

	if peer.device.isUp.Get() {
		peer.Start()
	}

	return peer, nil
}

func (peer *Peer) SendBuffer(buffer []byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.net.bind == nil {
		return errors.New("no bind")
	}

	peer.RLock()
	defer peer.RUnlock()

	if peer.endpoint == nil {
		return errors.New("no known endpoint for peer")
	}

	err := peer.device.net.bind.Send(buffer, peer.endpoint)
	if err == nil {
		atomic.AddUint64(&peer.stats.txBytes, uint64(len(buffer)))
	}
	return err
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

	peer.routines.Lock()
	defer peer.routines.Unlock()

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
	peer.queue.Lock()
	peer.queue.nonce = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.inbound = make(chan *QueueInboundElement, QueueInboundSize)
	peer.queue.Unlock()

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
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.loadNext())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.storeNext(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushNonceQueue()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce = RejectAfterMessages
	}
	if keypairs.next != nil {
		keypairs.loadNext().sendNonce = RejectAfterMessages
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {

	// prevent simultaneous start/stop operations

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.routines.starting.Wait()

	peer.routines.Lock()
	defer peer.routines.Unlock()

	peer.device.log.Debug.Println(peer, "- Stopping...")

	peer.timersStop()

	// stop & wait for ongoing peer routines

	close(peer.routines.stop)
	peer.routines.stopping.Wait()

	// close queues

	peer.queue.Lock()
	close(peer.queue.nonce)
	close(peer.queue.outbound)
	close(peer.queue.inbound)
	peer.queue.Unlock()

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	if peer.disableRoaming {
		return
	}
	peer.Lock()
	peer.endpoint = endpoint
	peer.Unlock()
}
