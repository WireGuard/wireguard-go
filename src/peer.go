package main

import (
	"errors"
	"net"
	"sync"
	"time"
)

const ()

type Peer struct {
	id                          uint
	mutex                       sync.RWMutex
	endpoint                    *net.UDPAddr
	persistentKeepaliveInterval uint64
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	tx_bytes                    uint64
	rx_bytes                    uint64
	time                        struct {
		lastSend      time.Time // last send message
		lastHandshake time.Time // last completed handshake
	}
	signal struct {
		newKeyPair         chan struct{} // (size 1) : a new key pair was generated
		handshakeBegin     chan struct{} // (size 1) : request that a new handshake be started ("queue handshake")
		handshakeCompleted chan struct{} // (size 1) : handshake completed
		flushNonceQueue    chan struct{} // (size 1) : empty queued packets
		stop               chan struct{} // (size 0) : close to stop all goroutines for peer
	}
	timer struct {
		sendKeepalive    *time.Timer
		handshakeTimeout *time.Timer
	}
	queue struct {
		nonce    chan *QueueOutboundElement // nonce / pre-handshake queue
		outbound chan *QueueOutboundElement // sequential ordering of work
		inbound  chan *QueueInboundElement  // sequential ordering of work
	}
	mac MACStatePeer
}

func (device *Device) NewPeer(pk NoisePublicKey) *Peer {
	// create peer

	peer := new(Peer)
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	peer.mac.Init(pk)
	peer.device = device
	peer.timer.sendKeepalive = stoppedTimer()

	// assign id for debugging

	device.mutex.Lock()
	peer.id = device.idCounter
	device.idCounter += 1

	// map public key

	_, ok := device.peers[pk]
	if ok {
		panic(errors.New("bug: adding existing peer"))
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

	// prepare signaling

	peer.signal.stop = make(chan struct{})
	peer.signal.newKeyPair = make(chan struct{}, 1)
	peer.signal.handshakeBegin = make(chan struct{}, 1)
	peer.signal.handshakeCompleted = make(chan struct{}, 1)
	peer.signal.flushNonceQueue = make(chan struct{}, 1)

	// outbound pipeline

	go peer.RoutineNonce()
	go peer.RoutineHandshakeInitiator()
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	return peer
}

func (peer *Peer) Close() {
	close(peer.signal.stop)
}
