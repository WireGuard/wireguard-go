package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	PeerRoutineNumber = 4
)

type Peer struct {
	id                          uint
	mutex                       sync.RWMutex
	persistentKeepaliveInterval uint64
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	endpoint                    Endpoint
	stats                       struct {
		txBytes           uint64 // bytes send to peer (endpoint)
		rxBytes           uint64 // bytes received from peer
		lastHandshakeNano int64  // nano seconds since epoch
	}
	time struct {
		mutex         sync.RWMutex
		lastSend      time.Time // last send message
		lastHandshake time.Time // last completed handshake
		nextKeepalive time.Time
	}
	signal struct {
		newKeyPair         Signal // size 1, new key pair was generated
		handshakeCompleted Signal // size 1, handshake completed
		handshakeBegin     Signal // size 1, begin new handshake begin
		flushNonceQueue    Signal // size 1, empty queued packets
		messageSend        Signal // size 1, message was send to peer
		messageReceived    Signal // size 1, authenticated message recv
	}
	timer struct {
		// state related to WireGuard timers

		keepalivePersistent Timer // set for persistent keepalives
		keepalivePassive    Timer // set upon recieving messages
		zeroAllKeys         Timer // zero all key material
		handshakeNew        Timer // begin a new handshake (stale)
		handshakeDeadline   Timer // complete handshake timeout
		handshakeTimeout    Timer // current handshake message timeout

		sendLastMinuteHandshake bool
		needAnotherKeepalive    bool
	}
	queue struct {
		nonce    chan *QueueOutboundElement // nonce / pre-handshake queue
		outbound chan *QueueOutboundElement // sequential ordering of work
		inbound  chan *QueueInboundElement  // sequential ordering of work
	}
	routines struct {
		mutex    sync.Mutex     // held when stopping / starting routines
		starting sync.WaitGroup // routines pending start
		stopping sync.WaitGroup // routines pending stop
		stop     Signal         // size 0, stop all goroutines in peer
	}
	mac CookieGenerator
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	// create peer

	peer := new(Peer)
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	peer.mac.Init(pk)
	peer.device = device

	peer.timer.keepalivePersistent = NewTimer()
	peer.timer.keepalivePassive = NewTimer()
	peer.timer.zeroAllKeys = NewTimer()
	peer.timer.handshakeNew = NewTimer()
	peer.timer.handshakeDeadline = NewTimer()
	peer.timer.handshakeTimeout = NewTimer()

	// assign id for debugging

	device.mutex.Lock()
	peer.id = device.idCounter
	device.idCounter += 1

	// check if over limit

	if len(device.peers) >= MaxPeers {
		return nil, errors.New("Too many peers")
	}

	// map public key

	_, ok := device.peers[pk]
	if ok {
		return nil, errors.New("Adding existing peer")
	}
	device.peers[pk] = peer
	device.mutex.Unlock()

	// precompute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic =
		device.privateKey.sharedSecret(handshake.remoteStatic)
	handshake.mutex.Unlock()

	// reset endpoint

	peer.endpoint = nil

	// prepare queuing

	peer.queue.nonce = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.inbound = make(chan *QueueInboundElement, QueueInboundSize)

	// prepare signaling & routines

	peer.signal.newKeyPair = NewSignal()
	peer.signal.handshakeBegin = NewSignal()
	peer.signal.handshakeCompleted = NewSignal()
	peer.signal.flushNonceQueue = NewSignal()

	peer.routines.mutex.Lock()
	peer.routines.stop = NewSignal()
	peer.routines.mutex.Unlock()

	return peer, nil
}

func (peer *Peer) SendBuffer(buffer []byte) error {
	peer.device.net.mutex.RLock()
	defer peer.device.net.mutex.RUnlock()

	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	if peer.endpoint == nil {
		return errors.New("No known endpoint for peer")
	}

	return peer.device.net.bind.Send(buffer, peer.endpoint)
}

/* Returns a short string identifier for logging
 */
func (peer *Peer) String() string {
	if peer.endpoint == nil {
		return fmt.Sprintf(
			"peer(%d unknown %s)",
			peer.id,
			base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:]),
		)
	}
	return fmt.Sprintf(
		"peer(%d %s %s)",
		peer.id,
		peer.endpoint.DstToString(),
		base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:]),
	)
}

func (peer *Peer) Start() {

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Lock()

	// stop & wait for ungoing routines (if any)

	peer.routines.stop.Broadcast()
	peer.routines.starting.Wait()
	peer.routines.stopping.Wait()

	// reset signal and start (new) routines

	peer.routines.stop = NewSignal()
	peer.routines.starting.Add(PeerRoutineNumber)
	peer.routines.stopping.Add(PeerRoutineNumber)

	go peer.RoutineNonce()
	go peer.RoutineTimerHandler()
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	peer.routines.starting.Wait()
}

func (peer *Peer) Stop() {

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Lock()

	// stop & wait for ungoing routines (if any)

	peer.routines.stop.Broadcast()
	peer.routines.starting.Wait()
	peer.routines.stopping.Wait()

	// reset signal (to handle repeated stopping)

	peer.routines.stop = NewSignal()
}
