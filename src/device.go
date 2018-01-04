package main

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type Device struct {
	closed    AtomicBool // device is closed? (acting as guard)
	log       *Logger    // collection of loggers for levels
	idCounter uint       // for assigning debug ids to peers
	fwMark    uint32
	tun       struct {
		device TUNDevice
		isUp   AtomicBool
		mtu    int32
	}
	pool struct {
		messageBuffers sync.Pool
	}
	net struct {
		mutex  sync.RWMutex
		bind   Bind   // bind interface
		port   uint16 // listening port
		fwmark uint32 // mark value (0 = disabled)
	}
	mutex        sync.RWMutex
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

/* Warning:
 * The caller must hold the device mutex (write lock)
 */
func removePeerUnsafe(device *Device, key NoisePublicKey) {
	peer, ok := device.peers[key]
	if !ok {
		return
	}
	peer.mutex.Lock()
	device.routingTable.RemovePeer(peer)
	delete(device.peers, key)
	peer.Close()
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

	// do DH precomputations

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

	device.log = logger
	device.peers = make(map[NoisePublicKey]*Peer)
	device.tun.device = tun
	device.tun.isUp.Set(false)

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
		peer.mutex.Lock()
		delete(device.peers, key)
		peer.Close()
		peer.mutex.Unlock()
	}
}

func (device *Device) Close() {
	if device.closed.Swap(true) {
		return
	}
	device.log.Info.Println("Closing device")
	device.RemoveAllPeers()
	device.signal.stop.Broadcast()
	device.tun.device.Close()
	closeBind(device)
}

func (device *Device) Wait() chan struct{} {
	return device.signal.stop.Wait()
}
