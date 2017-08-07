package main

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
)

type Device struct {
	mtu       int32
	tun       TUNDevice
	log       *Logger // collection of loggers for levels
	idCounter uint    // for assigning debug ids to peers
	fwMark    uint32
	pool      struct {
		// pools objects for reuse
		messageBuffers sync.Pool
	}
	net struct {
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
		encryption chan *QueueOutboundElement
		decryption chan *QueueInboundElement
		handshake  chan QueueHandshakeElement
	}
	signal struct {
		stop       chan struct{} // halts all go routines
		newUDPConn chan struct{} // a net.conn was set
	}
	isUp        int32 // atomic bool: interface is up
	underLoad   int32 // atomic bool: device is under load
	ratelimiter Ratelimiter
	peers       map[NoisePublicKey]*Peer
	mac         MACStateDevice
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

func NewDevice(tun TUNDevice, logLevel int) *Device {
	device := new(Device)

	device.mutex.Lock()
	defer device.mutex.Unlock()

	device.tun = tun
	device.log = NewLogger(logLevel)
	device.peers = make(map[NoisePublicKey]*Peer)
	device.indices.Init()
	device.ratelimiter.Init()
	device.routingTable.Reset()

	// listen

	device.net.mutex.Lock()
	device.net.conn, _ = net.ListenUDP("udp", device.net.addr)
	addr := device.net.conn.LocalAddr()
	device.net.addr, _ = net.ResolveUDPAddr(addr.Network(), addr.String())
	device.net.mutex.Unlock()

	// setup pools

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

	device.signal.stop = make(chan struct{})
	device.signal.newUDPConn = make(chan struct{}, 1)

	// start workers

	for i := 0; i < runtime.NumCPU(); i += 1 {
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	go device.RoutineBusyMonitor()
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()
	go device.RoutineReceiveIncomming()
	go device.ratelimiter.RoutineGarbageCollector(device.signal.stop)

	return device
}

func (device *Device) RoutineTUNEventReader() {
	events := device.tun.Events()
	logError := device.log.Error

	for event := range events {
		if event&TUNEventMTUUpdate != 0 {
			mtu, err := device.tun.MTU()
			if err != nil {
				logError.Println("Failed to load updated MTU of device:", err)
			} else {
				if mtu+MessageTransportSize > MaxMessageSize {
					mtu = MaxMessageSize - MessageTransportSize
				}
				atomic.StoreInt32(&device.mtu, int32(mtu))
			}
		}

		if event&TUNEventUp != 0 {
			println("handle 1")
			atomic.StoreInt32(&device.isUp, AtomicTrue)
			updateUDPConn(device)
			println("handle 2", device.net.conn)
		}

		if event&TUNEventDown != 0 {
			atomic.StoreInt32(&device.isUp, AtomicFalse)
			closeUDPConn(device)
		}
	}
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
	device.RemoveAllPeers()
	close(device.signal.stop)
}

func (device *Device) WaitChannel() chan struct{} {
	return device.signal.stop
}
