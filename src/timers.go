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
	peer.device.log.Debug.Println("Handshake completed")
	peer.timer.zeroAllKeys.Reset(RejectAfterTime * 3)
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

	timerStop(peer.timer.keepaliveAcknowledgement)
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

	writer := bytes.NewBuffer(elem.data[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	elem.packet = writer.Bytes()
	peer.mac.AddMacs(elem.packet)
	addToOutboundQueue(peer.queue.outbound, elem)
	return elem, err
}

func (peer *Peer) RoutineTimerHandler() {
	device := peer.device

	logDebug := device.log.Debug
	logDebug.Println("Routine, timer handler, started for peer", peer.id)

	for {
		select {

		case <-peer.signal.stop:
			return

		// keep-alives

		case <-peer.timer.keepalivePersistent.C:

			logDebug.Println("Sending persistent keep-alive to peer", peer.id)

			peer.SendKeepAlive()
			peer.TimerResetKeepalive()

		case <-peer.timer.keepaliveAcknowledgement.C:

			logDebug.Println("Sending passive persistent keep-alive to peer", peer.id)

			peer.SendKeepAlive()
			peer.TimerResetKeepalive()

		// clear key material

		case <-peer.timer.zeroAllKeys.C:

			logDebug.Println("Clearing all key material for peer", peer.id)

			// zero out key pairs

			func() {
				kp := &peer.keyPairs
				kp.mutex.Lock()
				// best we can do is wait for GC :( ?
				kp.current = nil
				kp.previous = nil
				kp.next = nil
				kp.mutex.Unlock()
			}()

			// zero out handshake

			func() {
				hs := &peer.handshake
				hs.mutex.Lock()
				hs.localEphemeral = NoisePrivateKey{}
				hs.remoteEphemeral = NoisePublicKey{}
				hs.chainKey = [blake2s.Size]byte{}
				hs.hash = [blake2s.Size]byte{}
				hs.mutex.Unlock()
			}()
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

	logError := device.log.Error
	logDebug := device.log.Debug
	logDebug.Println("Routine, handshake initator, started for peer", peer.id)

	for run := true; run; {
		var err error
		var attempts uint
		var deadline time.Time

		// wait for signal

		select {
		case <-peer.signal.handshakeBegin:
		case <-peer.signal.stop:
			return
		}

		// wait for handshake

		run = func() bool {
			for {
				// clear completed signal

				select {
				case <-peer.signal.handshakeCompleted:
				case <-peer.signal.stop:
					return false
				default:
				}

				// create initiation

				if elem != nil {
					elem.Drop()
				}
				elem, err = peer.BeginHandshakeInitiation()
				if err != nil {
					logError.Println("Failed to create initiation message:", err)
					break
				}

				// set timeout

				attempts += 1
				if attempts == 1 {
					deadline = time.Now().Add(MaxHandshakeAttemptTime)
				}
				timeout := time.NewTimer(RekeyTimeout)
				logDebug.Println("Handshake initiation attempt", attempts, "queued for peer", peer.id)

				// wait for handshake or timeout

				select {
				case <-peer.signal.stop:
					return true

				case <-peer.signal.handshakeCompleted:
					<-timeout.C
					return true

				case <-timeout.C:
					logDebug.Println("Timeout")

					// check if sufficient time for retry

					if deadline.Before(time.Now().Add(RekeyTimeout)) {
						signalSend(peer.signal.flushNonceQueue)
						timerStop(peer.timer.keepalivePersistent)
						timerStop(peer.timer.keepaliveAcknowledgement)
						return true
					}
				}
			}
			return true
		}()

		signalClear(peer.signal.handshakeBegin)
	}
}
