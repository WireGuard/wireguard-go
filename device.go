/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"./ratelimiter"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DeviceRoutineNumberPerCPU = 3
)

type Device struct {
	isUp     AtomicBool // device is (going) up
	isClosed AtomicBool // device is closed? (acting as guard)
	log      *Logger

	// synchronized resources (locks acquired in order)

	state struct {
		stopping sync.WaitGroup
		mutex    sync.Mutex
		changing AtomicBool
		current  bool
	}

	net struct {
		mutex  sync.RWMutex
		bind   Bind   // bind interface
		port   uint16 // listening port
		fwmark uint32 // mark value (0 = disabled)
	}

	noise struct {
		mutex      sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	routing struct {
		mutex sync.RWMutex
		table RoutingTable
	}

	peers struct {
		mutex  sync.RWMutex
		keyMap map[NoisePublicKey]*Peer
	}

	// unprotected / "self-synchronising resources"

	indices IndexTable
	mac     CookieChecker

	rate struct {
		underLoadUntil atomic.Value
		limiter        ratelimiter.Ratelimiter
	}

	pool struct {
		messageBuffers sync.Pool
	}

	queue struct {
		encryption chan *QueueOutboundElement
		decryption chan *QueueInboundElement
		handshake  chan QueueHandshakeElement
	}

	signal struct {
		stop Signal
	}

	tun struct {
		device TUNDevice
		mtu    int32
	}
}

/* Converts the peer into a "zombie", which remains in the peer map,
 * but processes no packets and does not exists in the routing table.
 *
 * Must hold:
 *  device.peers.mutex : exclusive lock
 *  device.routing     : exclusive lock
 */
func unsafeRemovePeer(device *Device, peer *Peer, key NoisePublicKey) {

	// stop routing and processing of packets

	device.routing.table.RemovePeer(peer)
	peer.Stop()

	// remove from peer map

	delete(device.peers.keyMap, key)
}

func deviceUpdateState(device *Device) {

	// check if state already being updated (guard)

	if device.state.changing.Swap(true) {
		return
	}

	// compare to current state of device

	device.state.mutex.Lock()

	newIsUp := device.isUp.Get()

	if newIsUp == device.state.current {
		device.state.changing.Set(false)
		device.state.mutex.Unlock()
		return
	}

	// change state of device

	switch newIsUp {
	case true:
		if err := device.BindUpdate(); err != nil {
			device.isUp.Set(false)
			break
		}
		device.peers.mutex.Lock()
		for _, peer := range device.peers.keyMap {
			peer.Start()
		}
		device.peers.mutex.Unlock()

	case false:
		device.BindClose()
		device.peers.mutex.Lock()
		for _, peer := range device.peers.keyMap {
			peer.Stop()
		}
		device.peers.mutex.Unlock()
	}

	// update state variables

	device.state.current = newIsUp
	device.state.changing.Set(false)
	device.state.mutex.Unlock()

	// check for state change in the mean time

	deviceUpdateState(device)
}

func (device *Device) Up() {

	// closed device cannot be brought up

	if device.isClosed.Get() {
		return
	}

	device.state.mutex.Lock()
	device.isUp.Set(true)
	device.state.mutex.Unlock()
	deviceUpdateState(device)
}

func (device *Device) Down() {
	device.state.mutex.Lock()
	device.isUp.Set(false)
	device.state.mutex.Unlock()
	deviceUpdateState(device)
}

func (device *Device) IsUnderLoad() bool {

	// check if currently under load

	now := time.Now()
	underLoad := len(device.queue.handshake) >= UnderLoadQueueSize
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(time.Second))
		return true
	}

	// check if recently under load

	until := device.rate.underLoadUntil.Load().(time.Time)
	return until.After(now)
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {

	// lock required resources

	device.noise.mutex.Lock()
	defer device.noise.mutex.Unlock()

	device.routing.mutex.Lock()
	defer device.routing.mutex.Unlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		defer peer.handshake.mutex.RUnlock()
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			unsafeRemovePeer(device, peer, key)
		}
	}

	// update key material

	device.noise.privateKey = sk
	device.noise.publicKey = publicKey
	device.mac.Init(publicKey)

	// do static-static DH pre-computations

	rmKey := device.noise.privateKey.IsZero()

	for key, peer := range device.peers.keyMap {

		hs := &peer.handshake

		if rmKey {
			hs.precomputedStaticStatic = [NoisePublicKeySize]byte{}
		} else {
			hs.precomputedStaticStatic = device.noise.privateKey.sharedSecret(hs.remoteStatic)
		}

		if isZero(hs.precomputedStaticStatic[:]) {
			unsafeRemovePeer(device, peer, key)
		}
	}

	return nil
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

func NewDevice(tun TUNDevice, logger *Logger) *Device {
	device := new(Device)

	device.isUp.Set(false)
	device.isClosed.Set(false)

	device.log = logger

	device.tun.device = tun
	mtu, err := device.tun.device.MTU()
	if err != nil {
		logger.Error.Println("Trouble determining MTU, assuming default:", err)
		mtu = DefaultMTU
	}
	device.tun.mtu = int32(mtu)

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)

	// initialize anti-DoS / anti-scanning features

	device.rate.limiter.Init()
	device.rate.underLoadUntil.Store(time.Time{})

	// initialize noise & crypt-key routine

	device.indices.Init()
	device.routing.table.Reset()

	// setup buffer pool

	device.pool.messageBuffers = sync.Pool{
		New: func() interface{} {
			return new([MaxMessageSize]byte)
		},
	}

	// create queues

	device.queue.handshake = make(chan QueueHandshakeElement, QueueHandshakeSize)
	device.queue.encryption = make(chan *QueueOutboundElement, QueueOutboundSize)
	device.queue.decryption = make(chan *QueueInboundElement, QueueInboundSize)

	// prepare signals

	device.signal.stop = NewSignal()

	// prepare net

	device.net.port = 0
	device.net.bind = nil

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Add(DeviceRoutineNumberPerCPU * cpus)
	for i := 0; i < cpus; i += 1 {
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.mutex.RLock()
	defer device.peers.mutex.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.noise.mutex.Lock()
	defer device.noise.mutex.Unlock()

	device.routing.mutex.Lock()
	defer device.routing.mutex.Unlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		unsafeRemovePeer(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
	device.noise.mutex.Lock()
	defer device.noise.mutex.Unlock()

	device.routing.mutex.Lock()
	defer device.routing.mutex.Unlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	for key, peer := range device.peers.keyMap {
		unsafeRemovePeer(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

func (device *Device) FlushPacketQueues() {
	for {
		select {
		case elem, ok := <-device.queue.decryption:
			if ok {
				elem.Drop()
			}
		case elem, ok := <-device.queue.encryption:
			if ok {
				elem.Drop()
			}
		case <-device.queue.handshake:
		default:
			return
		}
	}

}

func (device *Device) Close() {
	if device.isClosed.Swap(true) {
		return
	}
	device.log.Info.Println("Device closing")
	device.state.changing.Set(true)
	device.state.mutex.Lock()
	defer device.state.mutex.Unlock()

	device.tun.device.Close()
	device.BindClose()

	device.isUp.Set(false)

	device.signal.stop.Broadcast()

	device.state.stopping.Wait()
	device.FlushPacketQueues()

	device.RemoveAllPeers()
	device.rate.limiter.Close()

	device.state.changing.Set(false)
	device.log.Info.Println("Interface closed")
}

func (device *Device) Wait() chan struct{} {
	return device.signal.stop.Wait()
}
