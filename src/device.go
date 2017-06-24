package main

import (
	"sync"
)

type Device struct {
	mutex        sync.RWMutex
	peers        map[NoisePublicKey]*Peer
	indices      IndexTable
	privateKey   NoisePrivateKey
	publicKey    NoisePublicKey
	fwMark       uint32
	listenPort   uint16
	routingTable RoutingTable
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	// update key material

	device.privateKey = sk
	device.publicKey = sk.publicKey()

	// do precomputations

	for _, peer := range device.peers {
		h := &peer.handshake
		h.mutex.Lock()
		h.precomputedStaticStatic = device.privateKey.sharedSecret(h.remoteStatic)
		h.mutex.Unlock()
	}
}

func (device *Device) Init() {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	device.peers = make(map[NoisePublicKey]*Peer)
	device.indices.Init()
	device.listenPort = 0
	device.routingTable.Reset()
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.mutex.RLock()
	defer device.mutex.RUnlock()
	return device.peers[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	peer, ok := device.peers[key]
	if !ok {
		return
	}
	peer.mutex.Lock()
	device.routingTable.RemovePeer(peer)
	delete(device.peers, key)
}

func (device *Device) RemoveAllAllowedIps(peer *Peer) {

}

func (device *Device) RemoveAllPeers() {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	for key, peer := range device.peers {
		peer.mutex.Lock()
		device.routingTable.RemovePeer(peer)
		delete(device.peers, key)
		peer.mutex.Unlock()
	}
}
