package main

import (
	"bytes"
	"encoding/binary"
	"math/rand"
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
	nonce := atomic.LoadUint64(&kp.sendNonce)
	if nonce > RekeyAfterMessages {
		signalSend(peer.signal.handshakeBegin)
	}
	if kp.isInitiator && time.Now().Sub(kp.created) > RekeyAfterTime {
		signalSend(peer.signal.handshakeBegin)
	}
}

/* Called when a new authenticated message has been recevied
 *
 * NOTE: Not thread safe (called by sequential receiver)
 */
func (peer *Peer) KeepKeyFreshReceiving() {
	if peer.timer.sendLastMinuteHandshake {
		return
	}
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
		// do a last minute attempt at initiating a new handshake
		signalSend(peer.signal.handshakeBegin)
		peer.timer.sendLastMinuteHandshake = true
	}
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

/* Event:
 * Sent non-empty (authenticated) transport message
 */
func (peer *Peer) TimerDataSent() {
	timerStop(peer.timer.keepalivePassive)
	if !peer.timer.pendingNewHandshake {
		peer.timer.pendingNewHandshake = true
		peer.timer.newHandshake.Reset(NewHandshakeTime)
	}
}

/* Event:
 * Received non-empty (authenticated) transport message
 */
func (peer *Peer) TimerDataReceived() {
	if peer.timer.pendingKeepalivePassive {
		peer.timer.needAnotherKeepalive = true
		return
	}
	peer.timer.pendingKeepalivePassive = false
	peer.timer.keepalivePassive.Reset(KeepaliveTimeout)
}

/* Event:
 * Any (authenticated) packet received
 */
func (peer *Peer) TimerAnyAuthenticatedPacketReceived() {
	timerStop(peer.timer.newHandshake)
}

/* Event:
 * Any authenticated packet send / received.
 */
func (peer *Peer) TimerAnyAuthenticatedPacketTraversal() {
	interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
	if interval > 0 {
		duration := time.Duration(interval) * time.Second
		peer.timer.keepalivePersistent.Reset(duration)
	}
}

/* Called after succesfully completing a handshake.
 * i.e. after:
 *
 * - Valid handshake response
 * - First transport message under the "next" key
 */
func (peer *Peer) TimerHandshakeComplete() {
	atomic.StoreInt64(
		&peer.stats.lastHandshakeNano,
		time.Now().UnixNano(),
	)
	signalSend(peer.signal.handshakeCompleted)
	peer.device.log.Info.Println("Negotiated new handshake for", peer.String())
}

/* Event:
 * An ephemeral key is generated
 *
 * i.e after:
 *
 * CreateMessageInitiation
 * CreateMessageResponse
 *
 * Schedules the deletion of all key material
 * upon failure to complete a handshake
 */
func (peer *Peer) TimerEphemeralKeyCreated() {
	peer.timer.zeroAllKeys.Reset(RejectAfterTime * 3)
}

func (peer *Peer) RoutineTimerHandler() {
	device := peer.device

	logDebug := device.log.Debug
	logDebug.Println("Routine, timer handler, started for peer", peer.String())

	for {
		select {

		case <-peer.signal.stop:
			return

		// keep-alives

		case <-peer.timer.keepalivePersistent.C:

			interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
			if interval > 0 {
				logDebug.Println("Sending keep-alive to", peer.String())
				peer.SendKeepAlive()
			}

		case <-peer.timer.keepalivePassive.C:

			logDebug.Println("Sending keep-alive to", peer.String())

			peer.SendKeepAlive()

			if peer.timer.needAnotherKeepalive {
				peer.timer.keepalivePassive.Reset(KeepaliveTimeout)
				peer.timer.needAnotherKeepalive = false
			}

		// unresponsive session

		case <-peer.timer.newHandshake.C:

			logDebug.Println("Retrying handshake with", peer.String(), "due to lack of reply")

			signalSend(peer.signal.handshakeBegin)

		// clear key material

		case <-peer.timer.zeroAllKeys.C:

			logDebug.Println("Clearing all key material for", peer.String())

			hs := &peer.handshake
			hs.mutex.Lock()

			kp := &peer.keyPairs
			kp.mutex.Lock()

			// remove key-pairs

			if kp.previous != nil {
				device.DeleteKeyPair(kp.previous)
				kp.previous = nil
			}
			if kp.current != nil {
				device.DeleteKeyPair(kp.current)
				kp.current = nil
			}
			if kp.next != nil {
				device.DeleteKeyPair(kp.next)
				kp.next = nil
			}
			kp.mutex.Unlock()

			// zero out handshake

			device.indices.Delete(hs.localIndex)

			hs.localIndex = 0
			setZero(hs.localEphemeral[:])
			setZero(hs.remoteEphemeral[:])
			setZero(hs.chainKey[:])
			setZero(hs.hash[:])
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

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug
	logDebug.Println("Routine, handshake initator, started for", peer.String())

	var temp [256]byte

	for {

		// wait for signal

		select {
		case <-peer.signal.handshakeBegin:
		case <-peer.signal.stop:
			return
		}

		// set deadline

	BeginHandshakes:

		signalClear(peer.signal.handshakeReset)
		deadline := time.NewTimer(RekeyAttemptTime)

	AttemptHandshakes:

		for attempts := uint(1); ; attempts++ {

			// check if deadline reached

			select {
			case <-deadline.C:
				logInfo.Println("Handshake negotiation timed out for:", peer.String())
				signalSend(peer.signal.flushNonceQueue)
				timerStop(peer.timer.keepalivePersistent)
				break
			case <-peer.signal.stop:
				return
			default:
			}

			signalClear(peer.signal.handshakeCompleted)

			// create initiation message

			msg, err := peer.device.CreateMessageInitiation(peer)
			if err != nil {
				logError.Println("Failed to create handshake initiation message:", err)
				break AttemptHandshakes
			}

			jitter := time.Millisecond * time.Duration(rand.Uint32()%334)

			// marshal and send

			writer := bytes.NewBuffer(temp[:0])
			binary.Write(writer, binary.LittleEndian, msg)
			packet := writer.Bytes()
			peer.mac.AddMacs(packet)

			err = peer.SendBuffer(packet)
			if err != nil {
				logError.Println(
					"Failed to send handshake initiation message to",
					peer.String(), ":", err,
				)
				continue
			}

			peer.TimerAnyAuthenticatedPacketTraversal()

			// set handshake timeout

			timeout := time.NewTimer(RekeyTimeout + jitter)
			logDebug.Println(
				"Handshake initiation attempt",
				attempts, "sent to", peer.String(),
			)

			// wait for handshake or timeout

			select {

			case <-peer.signal.stop:
				return

			case <-peer.signal.handshakeCompleted:
				<-timeout.C
				peer.timer.sendLastMinuteHandshake = false
				break AttemptHandshakes

			case <-peer.signal.handshakeReset:
				<-timeout.C
				goto BeginHandshakes

			case <-timeout.C:
				// TODO: Clear source address for peer
				continue
			}
		}

		// clear signal set in the meantime

		signalClear(peer.signal.handshakeBegin)
	}
}
