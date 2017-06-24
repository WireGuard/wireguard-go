package main

import (
	"net"
	"sync"
	"time"
)

type Peer struct {
	mutex                       sync.RWMutex
	endpointIP                  net.IP        //
	endpointPort                uint16        //
	persistentKeepaliveInterval time.Duration // 0 = disabled
	handshake                   Handshake
	device                      *Device
}

func (device *Device) NewPeer(pk NoisePublicKey) *Peer {
	var peer Peer

	// map public key

	device.mutex.Lock()
	device.peers[pk] = &peer
	device.mutex.Unlock()

	// precompute

	peer.mutex.Lock()
	peer.device = device
	func(h *Handshake) {
		h.mutex.Lock()
		h.remoteStatic = pk
		h.precomputedStaticStatic = device.privateKey.sharedSecret(h.remoteStatic)
		h.mutex.Unlock()
	}(&peer.handshake)
	peer.mutex.Unlock()

	return &peer
}
