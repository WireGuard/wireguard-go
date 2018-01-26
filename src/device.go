package main

import (
	"github.com/sasha-s/go-deadlock"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type Device struct {
	isUp      AtomicBool // device is (going) up
	isClosed  AtomicBool // device is closed? (acting as guard)
	log       *Logger    // collection of loggers for levels
	idCounter uint       // for assigning debug ids to peers
	fwMark    uint32
	tun       struct {
		device TUNDevice
		mtu    int32
	}
	state struct {
		mutex    deadlock.Mutex
		changing AtomicBool
		current  bool
	}
	pool struct {
		messageBuffers sync.Pool
	}
	net struct {
		mutex  deadlock.RWMutex
		bind   Bind   // bind interface
		port   uint16 // listening port
		fwmark uint32 // mark value (0 = disabled)
	}
	mutex        deadlock.RWMutex
	privateKey   NoisePrivateKey
	publicKey    NoisePublicKey
	routingTable RoutingTable
	indices      IndexTable
	queue        struct {
		encryption chan *QueueOutboundElement
		decryption chan *QueueInboundElement
		handshake  chan QueueHandshakeElement
	}
	signal struct {
		stop Signal
	}
	underLoadUntil atomic.Value
	ratelimiter    Ratelimiter
	peers          map[NoisePublicKey]*Peer
	mac            CookieChecker
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
		device.state.mutex.Unlock()
		device.state.changing.Set(false)
		return
	}

	device.state.mutex.Unlock()

	// change state of device

	switch newIsUp {
	case true:

		// start listener

		if err := device.BindUpdate(); err != nil {
			device.isUp.Set(false)
			break
		}

		// start every peer

		for _, peer := range device.peers {
			peer.Start()
		}

	case false:

		// stop listening

		device.BindClose()

		// stop every peer

		for _, peer := range device.peers {
			peer.Stop()
		}
	}

	// update state variables
	// and check for state change in the mean time

	device.state.current = newIsUp
	device.state.changing.Set(false)
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

/* Warning:
 * The caller must hold the device mutex (write lock)
 */
func removePeerUnsafe(device *Device, key NoisePublicKey) {
	peer, ok := device.peers[key]
	if !ok {
		return
	}
	device.routingTable.RemovePeer(peer)
	delete(device.peers, key)
}

func (device *Device) IsUnderLoad() bool {

	// check if currently under load

	now := time.Now()
	underLoad := len(device.queue.handshake) >= UnderLoadQueueSize
	if underLoad {
		device.underLoadUntil.Store(now.Add(time.Second))
		return true
	}

	// check if recently under load

	until := device.underLoadUntil.Load().(time.Time)
	return until.After(now)
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers {
		h := &peer.handshake
		h.mutex.RLock()
		if h.remoteStatic.Equals(publicKey) {
			removePeerUnsafe(device, key)
		}
		h.mutex.RUnlock()
	}

	// update key material

	device.privateKey = sk
	device.publicKey = publicKey
	device.mac.Init(publicKey)

	// do DH pre-computations

	rmKey := device.privateKey.IsZero()

	for key, peer := range device.peers {
		h := &peer.handshake
		h.mutex.Lock()
		if rmKey {
			h.precomputedStaticStatic = [NoisePublicKeySize]byte{}
		} else {
			h.precomputedStaticStatic = device.privateKey.sharedSecret(h.remoteStatic)
			if isZero(h.precomputedStaticStatic[:]) {
				removePeerUnsafe(device, key)
			}
		}
		h.mutex.Unlock()
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
	device.mutex.Lock()
	defer device.mutex.Unlock()

	device.isUp.Set(false)
	device.isClosed.Set(false)

	device.log = logger
	device.peers = make(map[NoisePublicKey]*Peer)
	device.tun.device = tun

	device.indices.Init()
	device.ratelimiter.Init()

	device.routingTable.Reset()
	device.underLoadUntil.Store(time.Time{})

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

	for i := 0; i < runtime.NumCPU(); i += 1 {
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()
	go device.ratelimiter.RoutineGarbageCollector(device.signal.stop)

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
	removePeerUnsafe(device, key)
}

func (device *Device) RemoveAllPeers() {
	device.mutex.Lock()
	defer device.mutex.Unlock()

	for key, peer := range device.peers {
		peer.Stop()
		peer, ok := device.peers[key]
		if !ok {
			return
		}
		device.routingTable.RemovePeer(peer)
		delete(device.peers, key)
	}
}

func (device *Device) Close() {
	device.log.Info.Println("Device closing")
	if device.isClosed.Swap(true) {
		return
	}
	device.signal.stop.Broadcast()
	device.tun.device.Close()
	device.BindClose()
	device.isUp.Set(false)
	println("remove")
	device.RemoveAllPeers()
	device.log.Info.Println("Interface closed")
}

func (device *Device) Wait() chan struct{} {
	return device.signal.stop.Wait()
}
