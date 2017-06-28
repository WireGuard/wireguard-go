package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

/* Sends a keep-alive if no packets queued for peer
 *
 * Used by initiator of handshake and with active keep-alive
 */
func (peer *Peer) SendKeepAlive() bool {
	if len(peer.queue.nonce) == 0 {
		select {
		case peer.queue.nonce <- []byte{}:
			return true
		default:
			return false
		}
	}
	return true
}

func (peer *Peer) RoutineHandshakeInitiator() {
	var ongoing bool
	var begun time.Time
	var attempts uint
	var timeout time.Timer

	device := peer.device
	work := new(QueueOutboundElement)
	buffer := make([]byte, 0, 1024)

	queueHandshakeInitiation := func() error {
		work.mutex.Lock()
		defer work.mutex.Unlock()

		// create initiation

		msg, err := device.CreateMessageInitiation(peer)
		if err != nil {
			return err
		}

		// create "work" element

		writer := bytes.NewBuffer(buffer[:0])
		binary.Write(writer, binary.LittleEndian, &msg)
		work.packet = writer.Bytes()
		peer.mac.AddMacs(work.packet)
		peer.InsertOutbound(work)
		return nil
	}

	for {
		select {
		case <-peer.signal.stopInitiator:
			return

		case <-peer.signal.newHandshake:
			if ongoing {
				continue
			}

			// create handshake

			err := queueHandshakeInitiation()
			if err != nil {
				device.log.Error.Println("Failed to create initiation message:", err)
			}

			// log when we began

			begun = time.Now()
			ongoing = true
			attempts = 0
			timeout.Reset(RekeyTimeout)

		case <-peer.timer.sendKeepalive.C:

			// active keep-alives

			peer.SendKeepAlive()

		case <-peer.timer.handshakeTimeout.C:

			// check if we can stop trying

			if time.Now().Sub(begun) > MaxHandshakeAttempTime {
				peer.signal.flushNonceQueue <- true
				peer.timer.sendKeepalive.Stop()
				ongoing = false
				continue
			}

			// otherwise, try again (exponental backoff)

			attempts += 1
			err := queueHandshakeInitiation()
			if err != nil {
				device.log.Error.Println("Failed to create initiation message:", err)
			}
			peer.timer.handshakeTimeout.Reset((1 << attempts) * RekeyTimeout)
		}
	}
}

/* Handles packets related to handshake
 *
 *
 */
func (device *Device) HandshakeWorker(queue chan struct {
	msg     []byte
	msgType uint32
	addr    *net.UDPAddr
}) {
	for {
		elem := <-queue

		switch elem.msgType {
		case MessageInitiationType:
			if len(elem.msg) != MessageInitiationSize {
				continue
			}

			// check for cookie

			var msg MessageInitiation

			binary.Read(nil, binary.LittleEndian, &msg)

		case MessageResponseType:
			if len(elem.msg) != MessageResponseSize {
				continue
			}

			// check for cookie

		case MessageCookieReplyType:

		case MessageTransportType:
		}

	}
}

func (device *Device) KeepKeyFresh(peer *Peer) {

	send := func() bool {
		peer.keyPairs.mutex.RLock()
		defer peer.keyPairs.mutex.RUnlock()

		kp := peer.keyPairs.current
		if kp == nil {
			return false
		}

		nonce := atomic.LoadUint64(&kp.sendNonce)
		if nonce > RekeyAfterMessage {
			return true
		}

		return kp.isInitiator && time.Now().Sub(kp.created) > RekeyAfterTime
	}()

	if send {

	}
}
