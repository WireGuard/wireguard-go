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

/* Handles outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The order of packets (per peer) is maintained.
 * The functions in this file occure (roughly) in the order packets are processed.
 */

/* The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceeded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */
type QueueOutboundElement struct {
	dropped int32
	mutex   sync.Mutex
	data    [MaxMessageSize]byte // slice holding the packet data
	packet  []byte               // slice of "data" (always!)
	nonce   uint64               // nonce for encryption
	keyPair *KeyPair             // key-pair for encryption
	peer    *Peer                // related peer
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

/*
 * Assumption: The mutex of the returned element is released
 */
func (device *Device) NewOutboundElement() *QueueOutboundElement {
	// TODO: profile, consider sync.Pool
	elem := new(QueueOutboundElement)
	return elem
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
func (device *Device) RoutineReadFromTUN(tun TUNDevice) {

	if tun == nil {
		return
	}

	elem := device.NewOutboundElement()

	logDebug := device.log.Debug
	logError := device.log.Error

	logDebug.Println("Routine, TUN Reader: started")

	for {
		// read packet

		if elem == nil {
			elem = device.NewOutboundElement()
		}

		elem.packet = elem.data[MessageTransportHeaderSize:]
		size, err := tun.Read(elem.packet)
		if err != nil {

			// stop process

			logError.Println("Failed to read packet from TUN device:", err)
			device.Close()
			return
		}

		elem.packet = elem.packet[:size]
		if len(elem.packet) < ipv4.HeaderLen {
			logError.Println("Packet too short, length:", size)
			continue
		}

		// lookup peer

		var peer *Peer
		switch elem.packet[0] >> 4 {
		case ipv4.Version:
			dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
			peer = device.routingTable.LookupIPv4(dst)

		case ipv6.Version:
			dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer = device.routingTable.LookupIPv6(dst)

		default:
			logDebug.Println("Receieved packet with unknown IP version")
		}

		if peer == nil {
			continue
		}

		if peer.endpoint == nil {
			logDebug.Println("No known endpoint for peer", peer.String())
			continue
		}

		// insert into nonce/pre-handshake queue

		addToOutboundQueue(peer.queue.nonce, elem)
		elem = nil

	}
}

/* Queues packets when there is no handshake.
 * Then assigns nonces to packets sequentially
 * and creates "work" structs for workers
 *
 * TODO: Avoid dynamic allocation of work queue elements
 *
 * Obs. A single instance per peer
 */
func (peer *Peer) RoutineNonce() {
	var keyPair *KeyPair
	var elem *QueueOutboundElement

	device := peer.device
	logDebug := device.log.Debug
	logDebug.Println("Routine, nonce worker, started for peer", peer.String())

	func() {

		for {
		NextPacket:

			// wait for packet

			if elem == nil {
				select {
				case elem = <-peer.queue.nonce:
				case <-peer.signal.stop:
					return
				}
			}

			// wait for key pair

			for {
				select {
				case <-peer.signal.newKeyPair:
				default:
				}

				keyPair = peer.keyPairs.Current()
				if keyPair != nil && keyPair.sendNonce < RejectAfterMessages {
					if time.Now().Sub(keyPair.created) < RejectAfterTime {
						break
					}
				}
				signalSend(peer.signal.handshakeBegin)
				logDebug.Println("Awaiting key-pair for", peer.String())

				select {
				case <-peer.signal.newKeyPair:
					logDebug.Println("Key-pair negotiated for", peer.String())
					goto NextPacket

				case <-peer.signal.flushNonceQueue:
					logDebug.Println("Clearing queue for", peer.String())
					peer.FlushNonceQueue()
					elem = nil
					goto NextPacket

				case <-peer.signal.stop:
					return
				}
			}

			// process current packet

			if elem != nil {

				// create work element

				elem.keyPair = keyPair
				elem.nonce = atomic.AddUint64(&keyPair.sendNonce, 1) - 1
				elem.dropped = AtomicFalse
				elem.peer = peer
				elem.mutex.Lock()

				// add to parallel and sequential queue

				addToEncryptionQueue(device.queue.encryption, elem)
				addToOutboundQueue(peer.queue.outbound, elem)
				elem = nil
			}
		}
	}()
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption() {
	var nonce [chacha20poly1305.NonceSize]byte
	for work := range device.queue.encryption {

		// check if dropped

		if work.IsDropped() {
			continue
		}

		// populate header fields

		func() {
			header := work.data[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, work.keyPair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, work.nonce)
		}()

		// encrypt content

		binary.LittleEndian.PutUint64(nonce[4:], work.nonce)
		work.packet = work.keyPair.send.Seal(
			work.packet[:0],
			nonce[:],
			work.packet,
			nil,
		)
		length := MessageTransportHeaderSize + len(work.packet)
		work.packet = work.data[:length]
		work.mutex.Unlock()

		// refresh key if necessary

		work.peer.KeepKeyFreshSending()
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
		case <-peer.signal.stop:
			logDebug.Println("Routine, sequential sender, stopped for", peer.String())
			return

		case work := <-peer.queue.outbound:
			work.mutex.Lock()
			if work.IsDropped() {
				continue
			}

			func() {

				// send to endpoint

				peer.mutex.RLock()
				defer peer.mutex.RUnlock()

				if peer.endpoint == nil {
					logDebug.Println("No endpoint for", peer.String())
					return
				}

				device.net.mutex.RLock()
				defer device.net.mutex.RUnlock()

				if device.net.conn == nil {
					logDebug.Println("No source for device")
					return
				}

				_, err := device.net.conn.WriteToUDP(work.packet, peer.endpoint)
				if err != nil {
					return
				}
				atomic.AddUint64(&peer.txBytes, uint64(len(work.packet)))

				// reset keep-alive

				peer.TimerResetKeepalive()
			}()
		}
	}
}
