package main

import (
	"net"
	"runtime"
	"sync"
)

type Device struct {
	mtu          int
	fwMark       uint32
	address      *net.UDPAddr // UDP source address
	conn         *net.UDPConn // UDP "connection"
	mutex        sync.RWMutex
	privateKey   NoisePrivateKey
	publicKey    NoisePublicKey
	routingTable RoutingTable
	indices      IndexTable
	log          *Logger
	queue        struct {
		encryption chan *QueueOutboundElement // parallel work queue
	}
	peers map[NoisePublicKey]*Peer
	mac   MacStateDevice
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	// update key material

	device.privateKey = sk
	device.publicKey = sk.publicKey()
	device.mac.Init(device.publicKey)

	// do DH precomputations

	for _, peer := range device.peers {
		h := &peer.handshake
		h.mutex.Lock()
		h.precomputedStaticStatic = device.privateKey.sharedSecret(h.remoteStatic)
		h.mutex.Unlock()
	}
}

func NewDevice(tun TUNDevice) *Device {
	device := new(Device)

	device.mutex.Lock()
	defer device.mutex.Unlock()

	device.log = NewLogger()
	device.peers = make(map[NoisePublicKey]*Peer)
	device.indices.Init()
	device.routingTable.Reset()

	// start workers

	for i := 0; i < runtime.NumCPU(); i += 1 {
		go device.RoutineEncryption()
	}
	go device.RoutineReadFromTUN(tun)
	return device
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
