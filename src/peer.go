package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type Peer struct {
	id                          uint
	mutex                       sync.RWMutex
	persistentKeepaliveInterval uint64
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	endpoint                    *net.UDPAddr
	stats                       struct {
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
	signal struct {
		newKeyPair         chan struct{} // (size 1) : a new key pair was generated
		handshakeBegin     chan struct{} // (size 1) : request that a new handshake be started ("queue handshake")
		handshakeCompleted chan struct{} // (size 1) : handshake completed
		handshakeReset     chan struct{} // (size 1) : reset handshake negotiation state
		flushNonceQueue    chan struct{} // (size 1) : empty queued packets
		messageSend        chan struct{} // (size 1) : a message was send to the peer
		messageReceived    chan struct{} // (size 1) : an authenticated message was received
		stop               chan struct{} // (size 0) : close to stop all goroutines for peer
	}
	timer struct {
		// state related to WireGuard timers

		keepalivePersistent *time.Timer // set for persistent keepalives
		keepalivePassive    *time.Timer // set upon recieving messages
		newHandshake        *time.Timer // begin a new handshake (after Keepalive + RekeyTimeout)
		zeroAllKeys         *time.Timer // zero all key material (after RejectAfterTime*3)
		handshakeDeadline   *time.Timer // Current handshake must be completed

		pendingKeepalivePassive bool
		pendingNewHandshake     bool
		pendingZeroAllKeys      bool

		needAnotherKeepalive    bool
		sendLastMinuteHandshake bool
	}
	queue struct {
		nonce    chan *QueueOutboundElement // nonce / pre-handshake queue
		outbound chan *QueueOutboundElement // sequential ordering of work
		inbound  chan *QueueInboundElement  // sequential ordering of work
	}
	mac CookieGenerator
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	// create peer

	peer := new(Peer)
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	peer.mac.Init(pk)
	peer.device = device

	peer.timer.keepalivePersistent = NewStoppedTimer()
	peer.timer.keepalivePassive = NewStoppedTimer()
	peer.timer.newHandshake = NewStoppedTimer()
	peer.timer.zeroAllKeys = NewStoppedTimer()

	// assign id for debugging

	device.mutex.Lock()
	peer.id = device.idCounter
	device.idCounter += 1

	// check if over limit

	if len(device.peers) >= MaxPeers {
		return nil, errors.New("Too many peers")
	}

	// map public key

	_, ok := device.peers[pk]
	if ok {
		return nil, errors.New("Adding existing peer")
	}
	device.peers[pk] = peer
	device.mutex.Unlock()

	// precompute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic = device.privateKey.sharedSecret(handshake.remoteStatic)
	handshake.mutex.Unlock()

	// prepare queuing

	peer.queue.nonce = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.inbound = make(chan *QueueInboundElement, QueueInboundSize)

	// prepare signaling & routines

	peer.signal.stop = make(chan struct{})
	peer.signal.newKeyPair = make(chan struct{}, 1)
	peer.signal.handshakeBegin = make(chan struct{}, 1)
	peer.signal.handshakeReset = make(chan struct{}, 1)
	peer.signal.handshakeCompleted = make(chan struct{}, 1)
	peer.signal.flushNonceQueue = make(chan struct{}, 1)

	go peer.RoutineNonce()
	go peer.RoutineTimerHandler()
	go peer.RoutineHandshakeInitiator()
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	return peer, nil
}

func (peer *Peer) String() string {
	return fmt.Sprintf(
		"peer(%d %s %s)",
		peer.id,
		peer.endpoint.String(),
		base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:]),
	)
}

func (peer *Peer) Close() {
	close(peer.signal.stop)
}
