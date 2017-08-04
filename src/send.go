package main

import (
	"encoding/binary"
	"errors"
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
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "data" (always!)
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

var (
	ErrorNoEndpoint   = errors.New("No known endpoint for peer")
	ErrorNoConnection = errors.New("No UDP socket for device")
)

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
				old.Drop()
				old.mutex.Unlock()
			default:
			}
		}
	}
}

func (peer *Peer) SendBuffer(buffer []byte) (int, error) {
	peer.device.net.mutex.RLock()
	defer peer.device.net.mutex.RUnlock()

	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	endpoint := peer.endpoint
	conn := peer.device.net.conn

	if endpoint == nil {
		return 0, ErrorNoEndpoint
	}

	if conn == nil {
		return 0, ErrorNoConnection
	}

	return conn.WriteToUDP(buffer, endpoint)
}

/* Reads packets from the TUN and inserts
 * into nonce queue for peer
 *
 * Obs. Single instance per TUN device
 */
func (device *Device) RoutineReadFromTUN() {

	if device.tun == nil {
		return
	}

	var elem *QueueOutboundElement

	logDebug := device.log.Debug
	logError := device.log.Error

	logDebug.Println("Routine, TUN Reader: started")

	for {
		// read packet

		if elem == nil {
			elem = device.NewOutboundElement()
		}

		// TODO: THIS!
		elem.packet = elem.buffer[MessageTransportHeaderSize:]
		size, err := device.tun.Read(elem.packet)
		if err != nil {
			logError.Println("Failed to read packet from TUN device:", err)
			device.Close()
			return
		}

		if size == 0 {
			continue
		}

		println(size, err)

		elem.packet = elem.packet[:size]

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
			logDebug.Println("Receieved packet with unknown IP version")
		}

		if peer == nil {
			continue
		}

		// check if known endpoint

		peer.mutex.RLock()
		if peer.endpoint == nil {
			peer.mutex.RUnlock()
			logDebug.Println("No known endpoint for peer", peer.String())
			continue
		}
		peer.mutex.RUnlock()

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

	var elem *QueueOutboundElement
	var nonce [chacha20poly1305.NonceSize]byte

	logDebug := device.log.Debug
	logDebug.Println("Routine, encryption worker, started")

	for {

		// fetch next element

		select {
		case elem = <-device.queue.encryption:
		case <-device.signal.stop:
			logDebug.Println("Routine, encryption worker, stopped")
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
		binary.LittleEndian.PutUint32(fieldReceiver, elem.keyPair.remoteIndex)
		binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

		// pad content to MTU size

		mtu := int(atomic.LoadInt32(&device.mtu))
		pad := len(elem.packet) % PaddingMultiple
		if pad > 0 {
			for i := 0; i < PaddingMultiple-pad && len(elem.packet) < mtu; i++ {
				elem.packet = append(elem.packet, 0)
			}
			// TODO: How good is this code
		}

		// encrypt content (append to header)

		binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
		elem.packet = elem.keyPair.send.Seal(
			header,
			nonce[:],
			elem.packet,
			nil,
		)
		elem.mutex.Unlock()

		// refresh key if necessary

		elem.peer.KeepKeyFreshSending()
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

		case elem := <-peer.queue.outbound:
			elem.mutex.Lock()
			if elem.IsDropped() {
				continue
			}

			// send message and return buffer to pool

			length := uint64(len(elem.packet))
			_, err := peer.SendBuffer(elem.packet)
			device.PutMessageBuffer(elem.buffer)
			if err != nil {
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
