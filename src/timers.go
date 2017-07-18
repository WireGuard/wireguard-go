package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/blake2s"
	"sync/atomic"
	"time"
)

/* Called when a new authenticated message has been send
 *
 */
func (peer *Peer) KeepKeyFreshSending() {
	kp := peer.keyPairs.Current()
	if kp == nil {
		return
	}
	if !kp.isInitiator {
		return
	}
	nonce := atomic.LoadUint64(&kp.sendNonce)
	send := nonce > RekeyAfterMessages || time.Now().Sub(kp.created) > RekeyAfterTime
	if send {
		signalSend(peer.signal.handshakeBegin)
	}
}

/* Called when a new authenticated message has been recevied
 *
 */
func (peer *Peer) KeepKeyFreshReceiving() {
	kp := peer.keyPairs.Current()
	if kp == nil {
		return
	}
	if !kp.isInitiator {
		return
	}
	nonce := atomic.LoadUint64(&kp.sendNonce)
	send := nonce > RekeyAfterMessages || time.Now().Sub(kp.created) > RekeyAfterTimeReceiving
	if send {
		signalSend(peer.signal.handshakeBegin)
	}
}

/* Called after succesfully completing a handshake.
 * i.e. after:
 * - Valid handshake response
 * - First transport message under the "next" key
 */
func (peer *Peer) EventHandshakeComplete() {
	peer.device.log.Info.Println("Negotiated new handshake for", peer.String())
	peer.timer.zeroAllKeys.Reset(RejectAfterTime * 3)
	atomic.StoreInt64(
		&peer.stats.lastHandshakeNano,
		time.Now().UnixNano(),
	)
	signalSend(peer.signal.handshakeCompleted)
}

/* Queues a keep-alive if no packets are queued for peer
 */
func (peer *Peer) SendKeepAlive() bool {
	elem := peer.device.NewOutboundElement()
	elem.packet = nil
	if len(peer.queue.nonce) == 0 {
		select {
		case peer.queue.nonce <- elem:
			return true
		default:
			return false
		}
	}
	return true
}

/* Starts the "keep-alive" timer
 * (if not already running),
 * in response to incomming messages
 */
func (peer *Peer) TimerStartKeepalive() {

	// check if acknowledgement timer set yet

	var waiting int32 = AtomicTrue
	waiting = atomic.SwapInt32(&peer.flags.keepaliveWaiting, waiting)
	if waiting == AtomicTrue {
		return
	}

	// timer not yet set, start it

	wait := KeepaliveTimeout
	interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
	if interval > 0 {
		duration := time.Duration(interval) * time.Second
		if duration < wait {
			wait = duration
		}
	}
}

/* Resets both keep-alive timers
 */
func (peer *Peer) TimerResetKeepalive() {

	// reset persistent timer

	interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
	if interval > 0 {
		peer.timer.keepalivePersistent.Reset(
			time.Duration(interval) * time.Second,
		)
	}

	// stop acknowledgement timer

	timerStop(peer.timer.keepalivePassive)
	atomic.StoreInt32(&peer.flags.keepaliveWaiting, AtomicFalse)
}

func (peer *Peer) BeginHandshakeInitiation() (*QueueOutboundElement, error) {

	// create initiation

	elem := peer.device.NewOutboundElement()
	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		return nil, err
	}

	// marshal & schedule for sending

	writer := bytes.NewBuffer(elem.buffer[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	elem.packet = writer.Bytes()
	peer.mac.AddMacs(elem.packet)
	addToOutboundQueue(peer.queue.outbound, elem)
	return elem, err
}

func (peer *Peer) RoutineTimerHandler() {
	device := peer.device
	indices := &device.indices

	logDebug := device.log.Debug
	logDebug.Println("Routine, timer handler, started for peer", peer.String())

	for {
		select {

		case <-peer.signal.stop:
			return

		// keep-alives

		case <-peer.timer.keepalivePersistent.C:

			logDebug.Println("Sending persistent keep-alive to", peer.String())

			peer.SendKeepAlive()
			peer.TimerResetKeepalive()

		case <-peer.timer.keepalivePassive.C:

			logDebug.Println("Sending passive persistent keep-alive to", peer.String())

			peer.SendKeepAlive()
			peer.TimerResetKeepalive()

		// clear key material

		case <-peer.timer.zeroAllKeys.C:

			logDebug.Println("Clearing all key material for", peer.String())

			kp := &peer.keyPairs
			kp.mutex.Lock()

			hs := &peer.handshake
			hs.mutex.Lock()

			// unmap local indecies

			indices.mutex.Lock()
			if kp.previous != nil {
				delete(indices.table, kp.previous.localIndex)
			}
			if kp.current != nil {
				delete(indices.table, kp.current.localIndex)
			}
			if kp.next != nil {
				delete(indices.table, kp.next.localIndex)
			}
			delete(indices.table, hs.localIndex)
			indices.mutex.Unlock()

			// zero out key pairs (TODO: better than wait for GC)

			kp.current = nil
			kp.previous = nil
			kp.next = nil
			kp.mutex.Unlock()

			// zero out handshake

			hs.localIndex = 0
			hs.localEphemeral = NoisePrivateKey{}
			hs.remoteEphemeral = NoisePublicKey{}
			hs.chainKey = [blake2s.Size]byte{}
			hs.hash = [blake2s.Size]byte{}
			hs.mutex.Unlock()
		}
	}
}

/* This is the state machine for handshake initiation
 *
 * Associated with this routine is the signal "handshakeBegin"
 * The routine will read from the "handshakeBegin" channel
 * at most every RekeyTimeout seconds
 */
func (peer *Peer) RoutineHandshakeInitiator() {
	device := peer.device

	var elem *QueueOutboundElement

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug
	logDebug.Println("Routine, handshake initator, started for", peer.String())

	for {

		// wait for signal

		select {
		case <-peer.signal.handshakeBegin:
		case <-peer.signal.stop:
			return
		}

		// wait for handshake

		func() {
			var err error
			var deadline time.Time
			for attempts := uint(1); ; attempts++ {

				// clear completed signal

				select {
				case <-peer.signal.handshakeCompleted:
				case <-peer.signal.stop:
					return
				default:
				}

				// create initiation

				if elem != nil {
					elem.Drop()
				}
				elem, err = peer.BeginHandshakeInitiation()
				if err != nil {
					logError.Println("Failed to create initiation message", err, "for", peer.String())
					return
				}

				// set timeout

				if attempts == 1 {
					deadline = time.Now().Add(MaxHandshakeAttemptTime)
				}
				timeout := time.NewTimer(RekeyTimeout)
				logDebug.Println("Handshake initiation attempt", attempts, "queued for", peer.String())

				// wait for handshake or timeout

				select {

				case <-peer.signal.stop:
					return

				case <-peer.signal.handshakeCompleted:
					<-timeout.C
					return

				case <-timeout.C:
					if deadline.Before(time.Now().Add(RekeyTimeout)) {
						logInfo.Println("Handshake negotiation timed out for", peer.String())
						signalSend(peer.signal.flushNonceQueue)
						timerStop(peer.timer.keepalivePersistent)
						timerStop(peer.timer.keepalivePassive)
						return
					}
				}
			}
		}()

		signalClear(peer.signal.handshakeBegin)
	}
}
