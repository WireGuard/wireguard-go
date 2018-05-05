/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

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
	if peer.timer.sendLastMinuteHandshake.Get() {
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
		peer.timer.sendLastMinuteHandshake.Set(true)
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
	peer.event.dataSent.Fire()
}

/* Event:
 * Received non-empty (authenticated) transport message
 *
 * Action:
 * Set a timer to confirm the message using a keep-alive (if not already set)
 */
func (peer *Peer) TimerDataReceived() {
	peer.event.dataReceived.Fire()
	/*
		if !peer.timer.keepalivePassive.Start(KeepaliveTimeout) {
			peer.timer.needAnotherKeepalive.Set(true)
		}
	*/
}

/* Event:
 * Any (authenticated) packet received
 */
func (peer *Peer) TimerAnyAuthenticatedPacketReceived() {
	peer.event.anyAuthenticatedPacketReceived.Fire()
}

/* Event:
 * Any authenticated packet send / received.
 *
 * Action:
 * Push persistent keep-alive into the future
 */
func (peer *Peer) TimerAnyAuthenticatedPacketTraversal() {
	peer.event.anyAuthenticatedPacketTraversal.Fire()
}

/* Called after successfully completing a handshake.
 * i.e. after:
 *
 * - Valid handshake response
 * - First transport message under the "next" key
 */
func (peer *Peer) TimerHandshakeComplete() {
	peer.signal.handshakeCompleted.Send()
	peer.device.log.Info.Println(peer, ": New handshake completed")
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
	peer.event.ephemeralKeyCreated.Fire()
	// peer.timer.zeroAllKeys.Reset(RejectAfterTime * 3)
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

	return err
}

func newTimer() *time.Timer {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	return timer
}

func (peer *Peer) RoutineTimerHandler() {

	device := peer.device

	logInfo := device.log.Info
	logDebug := device.log.Debug

	defer func() {
		logDebug.Println(peer, ": Routine: timer handler - stopped")
		peer.routines.stopping.Done()
	}()

	logDebug.Println(peer, ": Routine: timer handler - started")

	// reset all timers

	pendingHandshakeNew := false
	pendingKeepalivePassive := false

	timerKeepalivePassive := newTimer()
	timerHandshakeDeadline := newTimer()
	timerHandshakeTimeout := newTimer()
	timerHandshakeNew := newTimer()
	timerZeroAllKeys := newTimer()
	timerKeepalivePersistent := newTimer()

	interval := peer.persistentKeepaliveInterval
	if interval > 0 {
		duration := time.Duration(interval) * time.Second
		timerKeepalivePersistent.Reset(duration)
	}

	// signal synchronised setup complete

	peer.routines.starting.Done()

	// handle timer events

	for {
		select {

		/* stopping */

		case <-peer.routines.stop.Wait():
			return

		/* events */

		case <-peer.event.dataSent.C:
			timerKeepalivePassive.Stop()
			if !pendingHandshakeNew {
				timerHandshakeNew.Reset(NewHandshakeTime)
			}

		case <-peer.event.dataReceived.C:
			if pendingKeepalivePassive {
				peer.timer.needAnotherKeepalive.Set(true) // TODO: make local
			} else {
				timerKeepalivePassive.Reset(KeepaliveTimeout)
			}

		case <-peer.event.anyAuthenticatedPacketTraversal.C:
			interval := peer.persistentKeepaliveInterval
			if interval > 0 {
				duration := time.Duration(interval) * time.Second
				timerKeepalivePersistent.Reset(duration)
			}

		/* timers */

		// keep-alive

		case <-timerKeepalivePersistent.C:

			interval := peer.persistentKeepaliveInterval
			if interval > 0 {
				logDebug.Println(peer, ": Send keep-alive (persistent)")
				timerKeepalivePassive.Stop()
				peer.SendKeepAlive()
			}

		case <-timerKeepalivePassive.C:

			logDebug.Println(peer, ": Send keep-alive (passive)")

			peer.SendKeepAlive()

			if peer.timer.needAnotherKeepalive.Swap(false) {
				timerKeepalivePassive.Reset(KeepaliveTimeout)
			}

		// clear key material timer

		case <-timerZeroAllKeys.C:

			logDebug.Println(peer, ": Clear all key-material (timer event)")

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

		case <-timerHandshakeNew.C:
			logInfo.Println(peer, ": Retrying handshake (timer event)")
			peer.signal.handshakeBegin.Send()

		case <-timerHandshakeTimeout.C:

			// clear source (in case this is causing problems)

			peer.mutex.Lock()
			if peer.endpoint != nil {
				peer.endpoint.ClearSrc()
			}
			peer.mutex.Unlock()

			// send new handshake

			err := peer.sendNewHandshake()

			// set timeout

			jitter := time.Millisecond * time.Duration(rand.Uint32()%334)
			timerKeepalivePassive.Stop()
			timerHandshakeTimeout.Reset(RekeyTimeout + jitter)

			if err != nil {
				logInfo.Println(peer, ": Failed to send handshake initiation", err)
			} else {
				logDebug.Println(peer, ": Send handshake initiation (subsequent)")
			}

		case <-timerHandshakeDeadline.C:

			// clear all queued packets and stop keep-alive

			logInfo.Println(peer, ": Handshake negotiation timed-out")

			peer.flushNonceQueue()
			signalSend(peer.signal.flushNonceQueue)
			timerKeepalivePersistent.Stop()
			peer.signal.handshakeBegin.Enable()

		/* signals */

		case <-peer.signal.handshakeBegin.Wait():

			peer.signal.handshakeBegin.Disable()

			err := peer.sendNewHandshake()

			// set timeout

			jitter := time.Millisecond * time.Duration(rand.Uint32()%334)
			timerKeepalivePassive.Stop()
			timerHandshakeTimeout.Reset(RekeyTimeout + jitter)

			if err != nil {
				logInfo.Println(peer, ": Failed to send handshake initiation", err)
			} else {
				logDebug.Println(peer, ": Send handshake initiation (initial)")
			}

			timerHandshakeDeadline.Reset(RekeyAttemptTime)

		case <-peer.signal.handshakeCompleted.Wait():

			logInfo.Println(peer, ": Handshake completed")

			atomic.StoreInt64(
				&peer.stats.lastHandshakeNano,
				time.Now().UnixNano(),
			)

			timerHandshakeTimeout.Stop()
			timerHandshakeDeadline.Stop()
			peer.signal.handshakeBegin.Enable()

			peer.timer.sendLastMinuteHandshake.Set(false)
		}
	}
}
