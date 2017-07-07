package main

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"time"
)

/* Sends a keep-alive if no packets queued for peer
 *
 * Used by initiator of handshake and with active keep-alive
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

/* Called when a new authenticated message has been send
 *
 * TODO: This might be done in a faster way
 */
func (peer *Peer) KeepKeyFreshSending() {
	send := func() bool {
		peer.keyPairs.mutex.RLock()
		defer peer.keyPairs.mutex.RUnlock()

		kp := peer.keyPairs.current
		if kp == nil {
			return false
		}

		if !kp.isInitiator {
			return false
		}

		nonce := atomic.LoadUint64(&kp.sendNonce)
		if nonce > RekeyAfterMessages {
			return true
		}
		return time.Now().Sub(kp.created) > RekeyAfterTime
	}()
	if send {
		sendSignal(peer.signal.handshakeBegin)
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
	logger := device.log.Debug
	timeout := stoppedTimer()

	var elem *QueueOutboundElement

	logger.Println("Routine, handshake initator, started for peer", peer.id)

	func() {
		for {
			var attempts uint
			var deadline time.Time

			// wait for signal

			select {
			case <-peer.signal.handshakeBegin:
			case <-peer.signal.stop:
				return
			}

		HandshakeLoop:
			for {
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
				elem = device.NewOutboundElement()

				msg, err := device.CreateMessageInitiation(peer)
				if err != nil {
					device.log.Error.Println("Failed to create initiation message:", err)
					break
				}

				// marshal & schedule for sending

				writer := bytes.NewBuffer(elem.data[:0])
				binary.Write(writer, binary.LittleEndian, msg)
				elem.packet = writer.Bytes()
				peer.mac.AddMacs(elem.packet)
				addToOutboundQueue(peer.queue.outbound, elem)

				if attempts == 0 {
					deadline = time.Now().Add(MaxHandshakeAttemptTime)
				}

				// set timeout

				attempts += 1
				stopTimer(timeout)
				timeout.Reset(RekeyTimeout)
				device.log.Debug.Println("Handshake initiation attempt", attempts, "queued for peer", peer.id)

				// wait for handshake or timeout

				select {
				case <-peer.signal.stop:
					return

				case <-peer.signal.handshakeCompleted:
					device.log.Debug.Println("Handshake complete")
					break HandshakeLoop

				case <-timeout.C:
					device.log.Debug.Println("Timeout")
					if deadline.Before(time.Now().Add(RekeyTimeout)) {
						peer.signal.flushNonceQueue <- struct{}{}
						if !peer.timer.sendKeepalive.Stop() {
							<-peer.timer.sendKeepalive.C
						}
						break HandshakeLoop
					}
				}
			}
		}
	}()

	logger.Println("Routine, handshake initator, stopped for peer", peer.id)
}
