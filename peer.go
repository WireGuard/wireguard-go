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
	isRunning                   AtomicBool
	mutex                       sync.RWMutex
	persistentKeepaliveInterval uint64
	keyPairs                    KeyPairs
	handshake                   Handshake
	device                      *Device
	endpoint                    Endpoint

	stats struct {
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

		keepalivePersistent Timer // set for persistent keep-alive
		keepalivePassive    Timer // set upon receiving messages
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
		stop     Signal         // size 0, stop all go-routines in peer
	}

	mac CookieGenerator
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {

	if device.isClosed.Get() {
		return nil, errors.New("Device closed")
	}

	// lock resources

	device.state.mutex.Lock()
	defer device.state.mutex.Unlock()

	device.noise.mutex.RLock()
	defer device.noise.mutex.RUnlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// check if over limit

	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("Too many peers")
	}

	// create peer

	peer := new(Peer)
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	peer.mac.Init(pk)
	peer.device = device
	peer.isRunning.Set(false)

	peer.timer.zeroAllKeys = NewTimer()
	peer.timer.keepalivePersistent = NewTimer()
	peer.timer.keepalivePassive = NewTimer()
	peer.timer.handshakeNew = NewTimer()
	peer.timer.handshakeDeadline = NewTimer()
	peer.timer.handshakeTimeout = NewTimer()

	// map public key

	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("Adding existing peer")
	}
	device.peers.keyMap[pk] = peer

	// pre-compute DH

	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.remoteStatic = pk
	handshake.precomputedStaticStatic = device.noise.privateKey.sharedSecret(pk)
	handshake.mutex.Unlock()

	// reset endpoint

	peer.endpoint = nil

	// prepare signaling & routines

	peer.routines.mutex.Lock()
	peer.routines.stop = NewSignal()
	peer.routines.mutex.Unlock()

	// start peer

	if peer.device.isUp.Get() {
		peer.Start()
	}

	return peer, nil
}

func (peer *Peer) SendBuffer(buffer []byte) error {
	peer.device.net.mutex.RLock()
	defer peer.device.net.mutex.RUnlock()

	if peer.device.net.bind == nil {
		return errors.New("No bind")
	}

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
			"peer(unknown %s)",
			base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:]),
		)
	}
	return fmt.Sprintf(
		"peer(%s %s)",
		peer.endpoint.DstToString(),
		base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:]),
	)
}

func (peer *Peer) Start() {

	// should never start a peer on a closed device

	if peer.device.isClosed.Get() {
		return
	}

	// prevent simultaneous start/stop operations

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Unlock()

	if peer.isRunning.Get() {
		return
	}

	device := peer.device
	device.log.Debug.Println(peer.String(), ": Starting...")

	// sanity check : these should be 0

	peer.routines.starting.Wait()
	peer.routines.stopping.Wait()

	// prepare queues and signals

	peer.signal.newKeyPair = NewSignal()
	peer.signal.handshakeBegin = NewSignal()
	peer.signal.handshakeCompleted = NewSignal()
	peer.signal.flushNonceQueue = NewSignal()

	peer.queue.nonce = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.outbound = make(chan *QueueOutboundElement, QueueOutboundSize)
	peer.queue.inbound = make(chan *QueueInboundElement, QueueInboundSize)

	peer.routines.stop = NewSignal()
	peer.isRunning.Set(true)

	// wait for routines to start

	peer.routines.starting.Add(PeerRoutineNumber)
	peer.routines.stopping.Add(PeerRoutineNumber)

	go peer.RoutineNonce()
	go peer.RoutineTimerHandler()
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	peer.routines.starting.Wait()
	peer.isRunning.Set(true)
}

func (peer *Peer) Stop() {

	// prevent simultaneous start/stop operations

	peer.routines.mutex.Lock()
	defer peer.routines.mutex.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	device := peer.device
	device.log.Debug.Println(peer.String(), ": Stopping...")

	// stop & wait for ongoing peer routines

	peer.routines.stop.Broadcast()
	peer.routines.starting.Wait()
	peer.routines.stopping.Wait()

	// stop timers

	peer.timer.keepalivePersistent.Stop()
	peer.timer.keepalivePassive.Stop()
	peer.timer.zeroAllKeys.Stop()
	peer.timer.handshakeNew.Stop()
	peer.timer.handshakeDeadline.Stop()
	peer.timer.handshakeTimeout.Stop()

	// close queues

	close(peer.queue.nonce)
	close(peer.queue.outbound)
	close(peer.queue.inbound)

	// close signals

	peer.signal.newKeyPair.Close()
	peer.signal.handshakeBegin.Close()
	peer.signal.handshakeCompleted.Close()
	peer.signal.flushNonceQueue.Close()

	// clear key pairs

	kp := &peer.keyPairs
	kp.mutex.Lock()

	device.DeleteKeyPair(kp.previous)
	device.DeleteKeyPair(kp.current)
	device.DeleteKeyPair(kp.next)

	kp.previous = nil
	kp.current = nil
	kp.next = nil
	kp.mutex.Unlock()

	// clear handshake state

	hs := &peer.handshake
	hs.mutex.Lock()
	device.indices.Delete(hs.localIndex)
	hs.Clear()
	hs.mutex.Unlock()
}
