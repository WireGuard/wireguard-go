package main

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sync/atomic"
	"time"
)

/* NOTE:
 * Notion of validity
 *
 *
 */

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
		peer.signal.handshakeBegin.Send()
	}
	if kp.isInitiator && time.Now().Sub(kp.created) > RekeyAfterTime {
		peer.signal.handshakeBegin.Send()
	}
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
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
		peer.timer.sendLastMinuteHandshake = true
		peer.signal.handshakeBegin.Send()
	}
}

/* Queues a keep-alive if no packets are queued for peer
 */
func (peer *Peer) SendKeepAlive() bool {
	if len(peer.queue.nonce) != 0 {
		return false
	}
	elem := peer.device.NewOutboundElement()
	elem.packet = nil
	select {
	case peer.queue.nonce <- elem:
		return true
	default:
		return false
	}
}

/* Event:
 * Sent non-empty (authenticated) transport message
 */
func (peer *Peer) TimerDataSent() {
	peer.timer.keepalivePassive.Stop()
	peer.timer.handshakeNew.Start(NewHandshakeTime)
}

/* Event:
 * Received non-empty (authenticated) transport message
 *
 * Action:
 * Set a timer to confirm the message using a keep-alive (if not already set)
 */
func (peer *Peer) TimerDataReceived() {
	if !peer.timer.keepalivePassive.Start(KeepaliveTimeout) {
		peer.timer.needAnotherKeepalive = true
	}
}

/* Event:
 * Any (authenticated) packet received
 */
func (peer *Peer) TimerAnyAuthenticatedPacketReceived() {
	peer.timer.handshakeNew.Stop()
}

/* Event:
 * Any authenticated packet send / received.
 *
 * Action:
 * Push persistent keep-alive into the future
 */
func (peer *Peer) TimerAnyAuthenticatedPacketTraversal() {
	interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
	if interval > 0 {
		duration := time.Duration(interval) * time.Second
		peer.timer.keepalivePersistent.Reset(duration)
	}
}

/* Called after successfully completing a handshake.
 * i.e. after:
 *
 * - Valid handshake response
 * - First transport message under the "next" key
 */
func (peer *Peer) TimerHandshakeComplete() {
	peer.signal.handshakeCompleted.Send()
	peer.device.log.Info.Println("Negotiated new handshake for", peer.String())
}

/* Event:
 * An ephemeral key is generated
 *
 * i.e. after:
 *
 * CreateMessageInitiation
 * CreateMessageResponse
 *
 * Action:
 * Schedule the deletion of all key material
 * upon failure to complete a handshake
 */
func (peer *Peer) TimerEphemeralKeyCreated() {
	peer.timer.zeroAllKeys.Reset(RejectAfterTime * 3)
}

/* Sends a new handshake initiation message to the peer (endpoint)
 */
func (peer *Peer) sendNewHandshake() error {

	// temporarily disable the handshake complete signal

	peer.signal.handshakeCompleted.Disable()

	// create initiation message

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		return err
	}

	// marshal handshake message

	var buff [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.mac.AddMacs(packet)

	// send to endpoint

	peer.TimerAnyAuthenticatedPacketTraversal()

	err = peer.SendBuffer(packet)
	if err == nil {
		peer.signal.handshakeCompleted.Enable()
	}

	// set timeout

	jitter := time.Millisecond * time.Duration(rand.Uint32()%334)

	peer.timer.keepalivePassive.Stop()
	peer.timer.handshakeTimeout.Reset(RekeyTimeout + jitter)

	return err
}

func (peer *Peer) RoutineTimerHandler() {

	defer peer.routines.stopping.Done()

	device := peer.device

	logInfo := device.log.Info
	logDebug := device.log.Debug
	logDebug.Println("Routine, timer handler, started for peer", peer.String())

	// reset all timers

	peer.timer.keepalivePassive.Stop()
	peer.timer.handshakeDeadline.Stop()
	peer.timer.handshakeTimeout.Stop()
	peer.timer.handshakeNew.Stop()
	peer.timer.zeroAllKeys.Stop()

	interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
	if interval > 0 {
		duration := time.Duration(interval) * time.Second
		peer.timer.keepalivePersistent.Reset(duration)
	}

	// signal synchronised setup complete

	peer.routines.starting.Done()

	// handle timer events

	for {
		select {

		/* stopping */

		case <-peer.routines.stop.Wait():
			return

		/* timers */

		// keep-alive

		case <-peer.timer.keepalivePersistent.Wait():

			interval := atomic.LoadUint64(&peer.persistentKeepaliveInterval)
			if interval > 0 {
				logDebug.Println(peer.String(), ": Send keep-alive (persistent)")
				peer.timer.keepalivePassive.Stop()
				peer.SendKeepAlive()
			}

		case <-peer.timer.keepalivePassive.Wait():

			logDebug.Println(peer.String(), ": Send keep-alive (passive)")

			peer.SendKeepAlive()

			if peer.timer.needAnotherKeepalive {
				peer.timer.needAnotherKeepalive = false
				peer.timer.keepalivePassive.Reset(KeepaliveTimeout)
			}

		// clear key material timer

		case <-peer.timer.zeroAllKeys.Wait():

			logDebug.Println(peer.String(), ": Clear all key-material (timer event)")

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
			hs.Clear()
			hs.mutex.Unlock()

		// handshake timers

		case <-peer.timer.handshakeNew.Wait():
			logInfo.Println(peer.String(), ": Retrying handshake (timer event)")
			peer.signal.handshakeBegin.Send()

		case <-peer.timer.handshakeTimeout.Wait():

			// clear source (in case this is causing problems)

			peer.mutex.Lock()
			if peer.endpoint != nil {
				peer.endpoint.ClearSrc()
			}
			peer.mutex.Unlock()

			// send new handshake

			err := peer.sendNewHandshake()

			if err != nil {
				logInfo.Println(peer.String(), ": Failed to send handshake initiation", err)
			} else {
				logDebug.Println(peer.String(), ": Send handshake initiation (subsequent)")
			}

		case <-peer.timer.handshakeDeadline.Wait():

			// clear all queued packets and stop keep-alive

			logInfo.Println(peer.String(), ": Handshake negotiation timed-out")

			peer.signal.flushNonceQueue.Send()
			peer.timer.keepalivePersistent.Stop()
			peer.signal.handshakeBegin.Enable()

		/* signals */

		case <-peer.signal.handshakeBegin.Wait():

			peer.signal.handshakeBegin.Disable()

			err := peer.sendNewHandshake()

			if err != nil {
				logInfo.Println(peer.String(), ": Failed to send handshake initiation", err)
			} else {
				logDebug.Println(peer.String(), ": Send handshake initiation (initial)")
			}

			peer.timer.handshakeDeadline.Reset(RekeyAttemptTime)

		case <-peer.signal.handshakeCompleted.Wait():

			logInfo.Println(peer.String(), ": Handshake completed")

			atomic.StoreInt64(
				&peer.stats.lastHandshakeNano,
				time.Now().UnixNano(),
			)

			peer.timer.handshakeTimeout.Stop()
			peer.timer.handshakeDeadline.Stop()
			peer.signal.handshakeBegin.Enable()

			peer.timer.sendLastMinuteHandshake = false
		}
	}
}
