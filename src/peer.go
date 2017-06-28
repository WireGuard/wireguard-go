package main

import (
	"errors"
	"net"
	"sync"
	"time"
)

const ()

type Peer struct {
	mutex                       sync.RWMutex
	endpoint                    *net.UDPAddr
	persistentKeepaliveInterval time.Duration // 0 = disabled
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	tx_bytes                    uint64
	rx_bytes                    uint64
	time                        struct {
		lastSend time.Time // last send message
	}
	signal struct {
		newHandshake    chan bool
		flushNonceQueue chan bool // empty queued packets
		stopSending     chan bool // stop sending pipeline
		stopInitiator   chan bool // stop initiator timer
	}
	timer struct {
		sendKeepalive    time.Timer
		handshakeTimeout time.Timer
	}
	queue struct {
		nonce    chan []byte                // nonce / pre-handshake queue
		outbound chan *QueueOutboundElement // sequential ordering of work
	}
	mac MacStatePeer
}

func (device *Device) NewPeer(pk NoisePublicKey) *Peer {
	var peer Peer

	// create peer

	peer.mutex.Lock()
	peer.device = device
	peer.keyPairs.Init()
	peer.mac.Init(pk)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.nonce = make(chan []byte, QueueOutboundSize)

	// map public key

	device.mutex.Lock()
	_, ok := device.peers[pk]
	if ok {
		panic(errors.New("bug: adding existing peer"))
	}
	device.peers[pk] = &peer
	device.mutex.Unlock()

	// precompute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic = device.privateKey.sharedSecret(handshake.remoteStatic)
	handshake.mutex.Unlock()
	peer.mutex.Unlock()

	// start workers

	peer.signal.stopSending = make(chan bool, 1)
	peer.signal.stopInitiator = make(chan bool, 1)
	peer.signal.newHandshake = make(chan bool, 1)
	peer.signal.flushNonceQueue = make(chan bool, 1)

	go peer.RoutineNonce()
	go peer.RoutineHandshakeInitiator()

	return &peer
}

func (peer *Peer) Close() {
	peer.signal.stopSending <- true
	peer.signal.stopInitiator <- true
}
