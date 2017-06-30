package main

import (
	"net"
	"runtime"
	"sync"
)

type Device struct {
	mtu       int
	log       *Logger // collection of loggers for levels
	idCounter uint    // for assigning debug ids to peers
	fwMark    uint32
	net       struct {
		// seperate for performance reasons
		mutex sync.RWMutex
		addr  *net.UDPAddr // UDP source address
		conn  *net.UDPConn // UDP "connection"
	}
	mutex        sync.RWMutex
	privateKey   NoisePrivateKey
	publicKey    NoisePublicKey
	routingTable RoutingTable
	indices      IndexTable
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

func NewDevice(tun TUNDevice, logLevel int) *Device {
	device := new(Device)

	device.mutex.Lock()
	defer device.mutex.Unlock()

	device.log = NewLogger(logLevel)
	device.peers = make(map[NoisePublicKey]*Peer)
	device.indices.Init()
	device.routingTable.Reset()

	// listen

	device.net.mutex.Lock()
	device.net.conn, _ = net.ListenUDP("udp", device.net.addr)
	addr := device.net.conn.LocalAddr()
	device.net.addr, _ = net.ResolveUDPAddr(addr.Network(), addr.String())
	device.net.mutex.Unlock()

	// create queues

	device.queue.encryption = make(chan *QueueOutboundElement, QueueOutboundSize)

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
	peer.Close()
}

func (device *Device) RemoveAllPeers() {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	for key, peer := range device.peers {
		peer.mutex.Lock()
		delete(device.peers, key)
		peer.Close()
		peer.mutex.Unlock()
	}
}

func (device *Device) Close() {
	device.RemoveAllPeers()
	close(device.queue.encryption)
}
