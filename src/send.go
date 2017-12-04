package main

import (
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
	keyPair *KeyPair              // key-pair for encryption
	peer    *Peer                 // related peer
}

func (peer *Peer) FlushNonceQueue() {
	elems := len(peer.queue.nonce)
	for i := 0; i < elems; i++ {
		select {
		case <-peer.queue.nonce:
		default:
			return
		}
	}
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

/* Reads packets from the TUN and inserts
 * into nonce queue for peer
 *
 * Obs. Single instance per TUN device
 */
func (device *Device) RoutineReadFromTUN() {

	elem := device.NewOutboundElement()

	logDebug := device.log.Debug
	logError := device.log.Error

	logDebug.Println("Routine, TUN Reader started")

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
			peer = device.routingTable.LookupIPv4(dst)

		case ipv6.Version:
			if len(elem.packet) < ipv6.HeaderLen {
				continue
			}
			dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer = device.routingTable.LookupIPv6(dst)

		default:
			logDebug.Println("Received packet with unknown IP version")
		}

		if peer == nil {
			continue
		}

		// insert into nonce/pre-handshake queue

		peer.timer.handshakeDeadline.Reset(RekeyAttemptTime)
		addToOutboundQueue(peer.queue.nonce, elem)
		elem = device.NewOutboundElement()
	}
}

/* Queues packets when there is no handshake.
 * Then assigns nonces to packets sequentially
 * and creates "work" structs for workers
 *
 * Obs. A single instance per peer
 */
func (peer *Peer) RoutineNonce() {
	var keyPair *KeyPair

	device := peer.device
	logDebug := device.log.Debug
	logDebug.Println("Routine, nonce worker, started for peer", peer.String())

	for {
	NextPacket:
		select {
		case <-peer.signal.stop.Wait():
			return

		case elem := <-peer.queue.nonce:

			// wait for key pair

			for {
				keyPair = peer.keyPairs.Current()
				if keyPair != nil && keyPair.sendNonce < RejectAfterMessages {
					if time.Now().Sub(keyPair.created) < RejectAfterTime {
						break
					}
				}

				peer.signal.handshakeBegin.Send()

				logDebug.Println("Awaiting key-pair for", peer.String())

				select {
				case <-peer.signal.newKeyPair.Wait():
				case <-peer.signal.flushNonceQueue.Wait():
					logDebug.Println("Clearing queue for", peer.String())
					peer.FlushNonceQueue()
					goto NextPacket
				case <-peer.signal.stop.Wait():
					return
				}
			}

			// populate work element

			elem.peer = peer
			elem.nonce = atomic.AddUint64(&keyPair.sendNonce, 1) - 1
			elem.keyPair = keyPair
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
	logDebug.Println("Routine, encryption worker, started")

	for {

		// fetch next element

		select {
		case <-device.signal.stop.Wait():
			logDebug.Println("Routine, encryption worker, stopped")
			return

		case elem := <-device.queue.encryption:

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
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keyPair.remoteIndex)
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
			elem.packet = elem.keyPair.send.Seal(
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
	logDebug.Println("Routine, sequential sender, started for", peer.String())

	for {
		select {

		case <-peer.signal.stop.Wait():
			logDebug.Println(
				"Routine, sequential sender, stopped for", peer.String())
			return

		case elem := <-peer.queue.outbound:
			elem.mutex.Lock()
			if elem.IsDropped() {
				continue
			}

			// send message and return buffer to pool

			length := uint64(len(elem.packet))
			err := peer.SendBuffer(elem.packet)
			device.PutMessageBuffer(elem.buffer)
			if err != nil {
				logDebug.Println("Failed to send authenticated packet to peer", peer.String())
				continue
			}
			atomic.AddUint64(&peer.stats.txBytes, length)

			// update timers

			peer.TimerAnyAuthenticatedPacketTraversal()
			if len(elem.packet) != MessageKeepaliveSize {
				peer.TimerDataSent()
			}
			peer.KeepKeyFreshSending()
		}
	}
}
