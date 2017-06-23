package main

import (
	"math/rand"
	"sync"
)

/* TODO: Locking may be a little broad here
 */

type Device struct {
	mutex        sync.RWMutex
	peers        map[NoisePublicKey]*Peer
	sessions     map[uint32]*Handshake
	privateKey   NoisePrivateKey
	publicKey    NoisePublicKey
	fwMark       uint32
	listenPort   uint16
	routingTable RoutingTable
}

func (dev *Device) NewID(h *Handshake) uint32 {
	dev.mutex.Lock()
	defer dev.mutex.Unlock()
	for {
		id := rand.Uint32()
		_, ok := dev.sessions[id]
		if !ok {
			dev.sessions[id] = h
			return id
		}
	}
}

func (dev *Device) RemovePeer(key NoisePublicKey) {
	dev.mutex.Lock()
	defer dev.mutex.Unlock()
	peer, ok := dev.peers[key]
	if !ok {
		return
	}
	peer.mutex.Lock()
	dev.routingTable.RemovePeer(peer)
	delete(dev.peers, key)
}

func (dev *Device) RemoveAllAllowedIps(peer *Peer) {

}

func (dev *Device) RemoveAllPeers() {
	dev.mutex.Lock()
	defer dev.mutex.Unlock()

	for key, peer := range dev.peers {
		peer.mutex.Lock()
		dev.routingTable.RemovePeer(peer)
		delete(dev.peers, key)
		peer.mutex.Unlock()
	}
}
