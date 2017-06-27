package main

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	OutboundQueueSize = 64
)

type Peer struct {
	mutex                       sync.RWMutex
	endpoint                    *net.UDPAddr
	persistentKeepaliveInterval time.Duration // 0 = disabled
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	queueInbound                chan []byte
	queueOutbound               chan *OutboundWorkQueueElement
	queueOutboundRouting        chan []byte
	mac                         MacStatePeer
}

func (device *Device) NewPeer(pk NoisePublicKey) *Peer {
	var peer Peer

	// create peer

	peer.mutex.Lock()
	peer.device = device
	peer.keyPairs.Init()
	peer.mac.Init(pk)
	peer.queueOutbound = make(chan *OutboundWorkQueueElement, OutboundQueueSize)

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

	return &peer
}
