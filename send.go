/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	dropped int32
	mutex   sync.Mutex
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *Keypair              // keypair for encryption
	peer    *Peer                 // related peer
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	return &QueueOutboundElement{
		dropped: AtomicFalse,
		buffer:  device.pool.messageBuffers.Get().(*[MaxMessageSize]byte),
	}
}

func (elem *QueueOutboundElement) Drop() {
	atomic.StoreInt32(&elem.dropped, AtomicTrue)
}

func (elem *QueueOutboundElement) IsDropped() bool {
	return atomic.LoadInt32(&elem.dropped) == AtomicTrue
}

func addToOutboundQueue(
	queue chan *QueueOutboundElement,
	element *QueueOutboundElement,
) {
	for {
		select {
		case queue <- element:
			return
		default:
			select {
			case old := <-queue:
				old.Drop()
			default:
			}
		}
	}
}

func addToEncryptionQueue(
	queue chan *QueueOutboundElement,
	element *QueueOutboundElement,
) {
	for {
		select {
		case queue <- element:
			return
		default:
			select {
			case old := <-queue:
				// drop & release to potential consumer
				old.Drop()
				old.mutex.Unlock()
			default:
			}
		}
	}
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() bool {
	if len(peer.queue.nonce) != 0 || peer.queue.packetInNonceQueueIsAwaitingKey || !peer.isRunning.Get() {
		return false
	}
	elem := peer.device.NewOutboundElement()
	elem.packet = nil
	select {
	case peer.queue.nonce <- elem:
		peer.device.log.Debug.Println(peer, ": Sending keepalive packet")
		return true
	default:
		return false
	}
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts = 0
	}

	peer.handshake.mutex.RLock()
	if time.Now().Sub(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Now().Sub(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Debug.Println(peer, ": Sending handshake initiation")

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Error.Println(peer, ": Failed to create initiation message:", err)
		return err
	}

	var buff [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()

	err = peer.SendBuffer(packet)
	if err != nil {
		peer.device.log.Error.Println(peer, ": Failed to send handshake initiation", err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Debug.Println(peer, ": Sending handshake response")

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Error.Println(peer, ": Failed to create response message:", err)
		return err
	}

	var buff [MessageResponseSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, response)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Error.Println(peer, ": Failed to derive keypair:", err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()

	err = peer.SendBuffer(packet)
	if err != nil {
		peer.device.log.Error.Println(peer, ": Failed to send handshake response", err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {

	device.log.Debug.Println("Sending cookie reply to:", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Error.Println("Failed to create cookie reply:", err)
		return err
	}

	var buff [MessageCookieReplySize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, reply)
	device.net.bind.Send(writer.Bytes(), initiatingElem.endpoint)
	if err != nil {
		device.log.Error.Println("Failed to send cookie reply:", err)
	}
	return err
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := atomic.LoadUint64(&keypair.sendNonce)
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Now().Sub(keypair.created) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

/* Reads packets from the TUN and inserts
 * into nonce queue for peer
 *
 * Obs. Single instance per TUN device
 */
func (device *Device) RoutineReadFromTUN() {

	elem := device.NewOutboundElement()

	logDebug := device.log.Debug
	logError := device.log.Error

	defer func() {
		logDebug.Println("Routine: TUN reader - stopped")
	}()

	logDebug.Println("Routine: TUN reader - started")

	for {

		// read packet

		offset := MessageTransportHeaderSize
		size, err := device.tun.device.Read(elem.buffer[:], offset)

		if err != nil {
			logError.Println("Failed to read packet from TUN device:", err)
			device.Close()
			return
		}

		if size == 0 || size > MaxContentSize {
			continue
		}

		elem.packet = elem.buffer[offset : offset+size]

		// lookup peer

		var peer *Peer
		switch elem.packet[0] >> 4 {
		case ipv4.Version:
			if len(elem.packet) < ipv4.HeaderLen {
				continue
			}
			dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
			peer = device.allowedips.LookupIPv4(dst)

		case ipv6.Version:
			if len(elem.packet) < ipv6.HeaderLen {
				continue
			}
			dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer = device.allowedips.LookupIPv6(dst)

		default:
			logDebug.Println("Received packet with unknown IP version")
		}

		if peer == nil {
			continue
		}

		// insert into nonce/pre-handshake queue

		if peer.isRunning.Get() {
			if peer.queue.packetInNonceQueueIsAwaitingKey {
				peer.SendHandshakeInitiation(false)
			}
			addToOutboundQueue(peer.queue.nonce, elem)
			elem = device.NewOutboundElement()
		}
	}
}

func (peer *Peer) FlushNonceQueue() {
	select {
	case peer.signals.flushNonceQueue <- struct{}{}:
	default:
	}
}

/* Queues packets when there is no handshake.
 * Then assigns nonces to packets sequentially
 * and creates "work" structs for workers
 *
 * Obs. A single instance per peer
 */
func (peer *Peer) RoutineNonce() {
	var keypair *Keypair

	device := peer.device
	logDebug := device.log.Debug

	defer func() {
		logDebug.Println(peer, ": Routine: nonce worker - stopped")
		peer.queue.packetInNonceQueueIsAwaitingKey = false
		peer.routines.stopping.Done()
	}()

	peer.routines.starting.Done()
	logDebug.Println(peer, ": Routine: nonce worker - started")

	for {
	NextPacket:
		peer.queue.packetInNonceQueueIsAwaitingKey = false

		select {
		case <-peer.routines.stop:
			return

		case elem, ok := <-peer.queue.nonce:

			if !ok {
				return
			}

			// wait for key pair

			for {
				keypair = peer.keypairs.Current()
				if keypair != nil && keypair.sendNonce < RejectAfterMessages {
					if time.Now().Sub(keypair.created) < RejectAfterTime {
						break
					}
				}
				peer.queue.packetInNonceQueueIsAwaitingKey = true

				select {
				case <-peer.signals.newKeypairArrived:
				default:
				}

				peer.SendHandshakeInitiation(false)

				logDebug.Println(peer, ": Awaiting keypair")

				select {
				case <-peer.signals.newKeypairArrived:
					logDebug.Println(peer, ": Obtained awaited keypair")
				case <-peer.signals.flushNonceQueue:
					for {
						select {
						case <-peer.queue.nonce:
						default:
							goto NextPacket
						}
					}
				case <-peer.routines.stop:
					return
				}
			}
			peer.queue.packetInNonceQueueIsAwaitingKey = false

			// populate work element

			elem.peer = peer
			elem.nonce = atomic.AddUint64(&keypair.sendNonce, 1) - 1
			// double check in case of race condition added by future code
			if elem.nonce >= RejectAfterMessages {
				goto NextPacket
			}
			elem.keypair = keypair
			elem.dropped = AtomicFalse
			elem.mutex.Lock()

			// add to parallel and sequential queue

			addToEncryptionQueue(device.queue.encryption, elem)
			addToOutboundQueue(peer.queue.outbound, elem)
		}
	}
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption() {

	var nonce [chacha20poly1305.NonceSize]byte

	logDebug := device.log.Debug

	defer func() {
		logDebug.Println("Routine: encryption worker - stopped")
		device.state.stopping.Done()
	}()

	logDebug.Println("Routine: encryption worker - started")

	for {

		// fetch next element

		select {
		case <-device.signals.stop:
			return

		case elem, ok := <-device.queue.encryption:

			if !ok {
				return
			}

			// check if dropped

			if elem.IsDropped() {
				continue
			}

			// populate header fields

			header := elem.buffer[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// pad content to multiple of 16

			mtu := int(atomic.LoadInt32(&device.tun.mtu))
			rem := len(elem.packet) % PaddingMultiple
			if rem > 0 {
				for i := 0; i < PaddingMultiple-rem && len(elem.packet) < mtu; i++ {
					elem.packet = append(elem.packet, 0)
				}
			}

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet,
				nil,
			)
			elem.mutex.Unlock()
		}
	}
}

/* Sequentially reads packets from queue and sends to endpoint
 *
 * Obs. Single instance per peer.
 * The routine terminates then the outbound queue is closed.
 */
func (peer *Peer) RoutineSequentialSender() {

	device := peer.device

	logDebug := device.log.Debug

	defer func() {
		logDebug.Println(peer, ": Routine: sequential sender - stopped")
		peer.routines.stopping.Done()
	}()

	logDebug.Println(peer, ": Routine: sequential sender - started")

	peer.routines.starting.Done()

	for {
		select {

		case <-peer.routines.stop:
			return

		case elem, ok := <-peer.queue.outbound:

			if !ok {
				return
			}

			elem.mutex.Lock()
			if elem.IsDropped() {
				continue
			}

			// send message and return buffer to pool

			length := uint64(len(elem.packet))
			err := peer.SendBuffer(elem.packet)
			device.PutMessageBuffer(elem.buffer)
			if err != nil {
				logDebug.Println("Failed to send authenticated packet to peer", peer)
				continue
			}
			atomic.AddUint64(&peer.stats.txBytes, length)

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			if len(elem.packet) != MessageKeepaliveSize {
				peer.timersDataSent()
			}
			peer.keepKeyFreshSending()
		}
	}
}
