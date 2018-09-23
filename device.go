/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"git.zx2c4.com/wireguard-go/ratelimiter"
	"git.zx2c4.com/wireguard-go/tun"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DeviceRoutineNumberPerCPU     = 3
	DeviceRoutineNumberAdditional = 2
)

type Device struct {
	isUp     AtomicBool // device is (going) up
	isClosed AtomicBool // device is closed? (acting as guard)
	log      *Logger

	// synchronized resources (locks acquired in order)

	state struct {
		starting sync.WaitGroup
		stopping sync.WaitGroup
		mutex    sync.Mutex
		changing AtomicBool
		current  bool
	}

	net struct {
		starting sync.WaitGroup
		stopping sync.WaitGroup
		mutex    sync.RWMutex
		bind     Bind   // bind interface
		port     uint16 // listening port
		fwmark   uint32 // mark value (0 = disabled)
	}

	staticIdentity struct {
		mutex      sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		mutex  sync.RWMutex
		keyMap map[NoisePublicKey]*Peer
	}

	// unprotected / "self-synchronising resources"

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	rate struct {
		underLoadUntil atomic.Value
		limiter        ratelimiter.Ratelimiter
	}

	pool struct {
		messageBufferPool        *sync.Pool
		messageBufferReuseChan   chan *[MaxMessageSize]byte
		inboundElementPool       *sync.Pool
		inboundElementReuseChan  chan *QueueInboundElement
		outboundElementPool      *sync.Pool
		outboundElementReuseChan chan *QueueOutboundElement
	}

	queue struct {
		encryption chan *QueueOutboundElement
		decryption chan *QueueInboundElement
		handshake  chan QueueHandshakeElement
	}

	signals struct {
		stop chan struct{}
	}

	tun struct {
		device tun.TUNDevice
		mtu    int32
	}
}

/* Converts the peer into a "zombie", which remains in the peer map,
 * but processes no packets and does not exists in the routing table.
 *
 * Must hold device.peers.mutex.
 */
func unsafeRemovePeer(device *Device, peer *Peer, key NoisePublicKey) {

	// stop routing and processing of packets

	device.allowedips.RemoveByPeer(peer)
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
		device.peers.mutex.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Start()
		}
		device.peers.mutex.RUnlock()

	case false:
		device.BindClose()
		device.peers.mutex.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Stop()
		}
		device.peers.mutex.RUnlock()
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

	device.isUp.Set(true)
	deviceUpdateState(device)
}

func (device *Device) Down() {
	device.isUp.Set(false)
	deviceUpdateState(device)
}

func (device *Device) IsUnderLoad() bool {

	// check if currently under load

	now := time.Now()
	underLoad := len(device.queue.handshake) >= UnderLoadQueueSize
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime))
		return true
	}

	// check if recently under load

	until := device.rate.underLoadUntil.Load().(time.Time)
	return until.After(now)
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {

	// lock required resources

	device.staticIdentity.mutex.Lock()
	defer device.staticIdentity.mutex.Unlock()

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

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	rmKey := device.staticIdentity.privateKey.IsZero()

	for key, peer := range device.peers.keyMap {

		handshake := &peer.handshake

		if rmKey {
			handshake.precomputedStaticStatic = [NoisePublicKeySize]byte{}
		} else {
			handshake.precomputedStaticStatic = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		}

		if isZero(handshake.precomputedStaticStatic[:]) {
			unsafeRemovePeer(device, peer, key)
		}
	}

	return nil
}

func NewDevice(tunDevice tun.TUNDevice, logger *Logger) *Device {
	device := new(Device)

	device.isUp.Set(false)
	device.isClosed.Set(false)

	device.log = logger

	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		logger.Error.Println("Trouble determining MTU, assuming default:", err)
		mtu = DefaultMTU
	}
	device.tun.mtu = int32(mtu)

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)

	device.rate.limiter.Init()
	device.rate.underLoadUntil.Store(time.Time{})

	device.indexTable.Init()
	device.allowedips.Reset()

	device.PopulatePools()

	// create queues

	device.queue.handshake = make(chan QueueHandshakeElement, QueueHandshakeSize)
	device.queue.encryption = make(chan *QueueOutboundElement, QueueOutboundSize)
	device.queue.decryption = make(chan *QueueInboundElement, QueueInboundSize)

	// prepare signals

	device.signals.stop = make(chan struct{})

	// prepare net

	device.net.port = 0
	device.net.bind = nil

	// start workers

	cpus := runtime.NumCPU()
	device.state.starting.Wait()
	device.state.stopping.Wait()
	device.state.stopping.Add(DeviceRoutineNumberPerCPU*cpus + DeviceRoutineNumberAdditional)
	device.state.starting.Add(DeviceRoutineNumberPerCPU*cpus + DeviceRoutineNumberAdditional)
	for i := 0; i < cpus; i += 1 {
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	device.state.starting.Wait()

	return device
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.mutex.RLock()
	defer device.peers.mutex.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		unsafeRemovePeer(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
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

	device.state.starting.Wait()

	device.log.Info.Println("Device closing")
	device.state.changing.Set(true)
	device.state.mutex.Lock()
	defer device.state.mutex.Unlock()

	device.tun.device.Close()
	device.BindClose()

	device.isUp.Set(false)

	close(device.signals.stop)

	device.RemoveAllPeers()

	device.state.stopping.Wait()
	device.FlushPacketQueues()

	device.rate.limiter.Close()

	device.state.changing.Set(false)
	device.log.Info.Println("Interface closed")
}

func (device *Device) Wait() chan struct{} {
	return device.signals.stop
}
