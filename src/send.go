package main

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
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

/* A work unit
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work on the packet.
 */
type QueueOutboundElement struct {
	state   uint32
	mutex   sync.Mutex
	packet  []byte
	nonce   uint64
	keyPair *KeyPair
	peer    *Peer
}

func (peer *Peer) FlushNonceQueue() {
	elems := len(peer.queue.nonce)
	for i := 0; i < elems; i += 1 {
		select {
		case <-peer.queue.nonce:
		default:
			return
		}
	}
}

func (peer *Peer) InsertOutbound(elem *QueueOutboundElement) {
	for {
		select {
		case peer.queue.outbound <- elem:
			return
		default:
			select {
			case <-peer.queue.outbound:
			default:
			}
		}
	}
}

func (elem *QueueOutboundElement) Drop() {
	atomic.StoreUint32(&elem.state, ElementStateDropped)
}

func (elem *QueueOutboundElement) IsDropped() bool {
	return atomic.LoadUint32(&elem.state) == ElementStateDropped
}

/* Reads packets from the TUN and inserts
 * into nonce queue for peer
 *
 * Obs. Single instance per TUN device
 */
func (device *Device) RoutineReadFromTUN(tun TUNDevice) {
	if tun.MTU() == 0 {
		// Dummy
		return
	}

	device.log.Debug.Println("Routine, TUN Reader: started")
	for {
		// read packet

		packet := make([]byte, 1<<16) // TODO: Fix & avoid dynamic allocation
		size, err := tun.Read(packet)
		if err != nil {
			device.log.Error.Println("Failed to read packet from TUN device:", err)
			continue
		}
		packet = packet[:size]
		if len(packet) < IPv4headerSize {
			device.log.Error.Println("Packet too short, length:", len(packet))
			continue
		}

		// lookup peer

		var peer *Peer
		switch packet[0] >> 4 {
		case IPv4version:
			dst := packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
			peer = device.routingTable.LookupIPv4(dst)
			device.log.Debug.Println("New IPv4 packet:", packet, dst)

		case IPv6version:
			dst := packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer = device.routingTable.LookupIPv6(dst)
			device.log.Debug.Println("New IPv6 packet:", packet, dst)

		default:
			device.log.Debug.Println("Receieved packet with unknown IP version")
		}

		if peer == nil {
			device.log.Debug.Println("No peer configured for IP")
			continue
		}
		if peer.endpoint == nil {
			device.log.Debug.Println("No known endpoint for peer", peer.id)
			continue
		}

		// insert into nonce/pre-handshake queue

		for {
			select {
			case peer.queue.nonce <- packet:
			default:
				select {
				case <-peer.queue.nonce:
				default:
				}
				continue
			}
			break
		}
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
	var packet []byte
	var keyPair *KeyPair

	device := peer.device
	logger := device.log.Debug

	logger.Println("Routine, nonce worker, started for peer", peer.id)

	func() {

		for {
		NextPacket:

			// wait for packet

			if packet == nil {
				select {
				case packet = <-peer.queue.nonce:
				case <-peer.signal.stop:
					return
				}
			}

			logger.Println("PACKET:", packet)

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
				logger.Println("Key pair:", keyPair)

				sendSignal(peer.signal.handshakeBegin)
				logger.Println("Waiting for key-pair, peer", peer.id)

				select {
				case <-peer.signal.newKeyPair:
					logger.Println("Key-pair negotiated for peer", peer.id)
					goto NextPacket

				case <-peer.signal.flushNonceQueue:
					logger.Println("Clearing queue for peer", peer.id)
					peer.FlushNonceQueue()
					packet = nil
					goto NextPacket

				case <-peer.signal.stop:
					return
				}
			}

			// process current packet

			if packet != nil {

				// create work element

				work := new(QueueOutboundElement) // TODO: profile, maybe use pool
				work.keyPair = keyPair
				work.packet = packet
				work.nonce = atomic.AddUint64(&keyPair.sendNonce, 1) - 1
				work.peer = peer
				work.mutex.Lock()

				logger.Println("WORK:", work)

				packet = nil

				// drop packets until there is space

				func() {
					for {
						select {
						case peer.device.queue.encryption <- work:
							return
						default:
							select {
							case elem := <-peer.device.queue.encryption:
								elem.Drop()
							default:
							}
						}
					}
				}()
				peer.queue.outbound <- work
			}
		}
	}()

	logger.Println("Routine, nonce worker, stopped for peer", peer.id)
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption() {
	var nonce [chacha20poly1305.NonceSize]byte
	for work := range device.queue.encryption {
		if work.IsDropped() {
			continue
		}

		// pad packet

		padding := device.mtu - len(work.packet)
		if padding < 0 {
			work.Drop()
			continue
		}

		for n := 0; n < padding; n += 1 {
			work.packet = append(work.packet, 0)
		}
		device.log.Debug.Println(work.packet)

		// encrypt

		binary.LittleEndian.PutUint64(nonce[4:], work.nonce)
		work.packet = work.keyPair.send.Seal(
			work.packet[:0],
			nonce[:],
			work.packet,
			nil,
		)
		work.mutex.Unlock()

		// initiate new handshake

		work.peer.KeepKeyFreshSending()
	}
}

/* Sequentially reads packets from queue and sends to endpoint
 *
 * Obs. Single instance per peer.
 * The routine terminates then the outbound queue is closed.
 */
func (peer *Peer) RoutineSequentialSender() {
	logger := peer.device.log.Debug
	logger.Println("Routine, sequential sender, started for peer", peer.id)

	device := peer.device

	for {
		select {
		case <-peer.signal.stop:
			logger.Println("Routine, sequential sender, stopped for peer", peer.id)
			return
		case work := <-peer.queue.outbound:
			if work.IsDropped() {
				continue
			}
			work.mutex.Lock()
			func() {
				if work.packet == nil {
					return
				}

				peer.mutex.RLock()
				defer peer.mutex.RUnlock()

				if peer.endpoint == nil {
					logger.Println("No endpoint for peer:", peer.id)
					return
				}

				device.net.mutex.RLock()
				defer device.net.mutex.RUnlock()

				if device.net.conn == nil {
					logger.Println("No source for device")
					return
				}

				logger.Println(work.packet)

				_, err := device.net.conn.WriteToUDP(work.packet, peer.endpoint)
				if err != nil {
					return
				}
				atomic.AddUint64(&peer.tx_bytes, uint64(len(work.packet)))

				// shift keep-alive timer

				if peer.persistentKeepaliveInterval != 0 {
					interval := time.Duration(peer.persistentKeepaliveInterval) * time.Second
					peer.timer.sendKeepalive.Reset(interval)
				}
			}()
		}
	}
}
