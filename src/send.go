package main

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
	"sync"
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
	mutex   sync.Mutex
	packet  []byte
	nonce   uint64
	keyPair *KeyPair
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
		default:
			select {
			case <-peer.queue.outbound:
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
	device.log.Debug.Println("Routine, TUN Reader: started")
	for {
		// read packet

		device.log.Debug.Println("Read")
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
			return
		}

		if peer == nil {
			device.log.Debug.Println("No peer configured for IP")
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

	for {

		// wait for packet

		if packet == nil {
			select {
			case packet = <-peer.queue.nonce:
			case <-peer.signal.stopSending:
				close(peer.queue.outbound)
				return
			}
		}

		// wait for key pair

		for keyPair == nil {
			peer.signal.newHandshake <- true
			select {
			case <-peer.keyPairs.newKeyPair:
				keyPair = peer.keyPairs.Current()
				continue
			case <-peer.signal.flushNonceQueue:
				peer.FlushNonceQueue()
				packet = nil
				continue
			case <-peer.signal.stopSending:
				close(peer.queue.outbound)
				return
			}
		}

		// process current packet

		if packet != nil {

			// create work element

			work := new(QueueOutboundElement) // TODO: profile, maybe use pool
			work.keyPair = keyPair
			work.packet = packet
			work.nonce = keyPair.sendNonce
			work.mutex.Lock()

			packet = nil
			keyPair.sendNonce += 1

			// drop packets until there is space

			func() {
				for {
					select {
					case peer.device.queue.encryption <- work:
						return
					default:
						drop := <-peer.device.queue.encryption
						drop.packet = nil
						drop.mutex.Unlock()
					}
				}
			}()
			peer.queue.outbound <- work
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
	for work := range device.queue.encryption {

		// pad packet

		padding := device.mtu - len(work.packet)
		if padding < 0 {
			// drop
			work.packet = nil
			work.mutex.Unlock()
		}
		for n := 0; n < padding; n += 1 {
			work.packet = append(work.packet, 0)
		}

		// encrypt

		binary.LittleEndian.PutUint64(nonce[4:], work.nonce)
		work.packet = work.keyPair.send.Seal(
			work.packet[:0],
			nonce[:],
			work.packet,
			nil,
		)
		work.mutex.Unlock()
	}
}

/* Sequentially reads packets from queue and sends to endpoint
 *
 * Obs. Single instance per peer.
 * The routine terminates then the outbound queue is closed.
 */
func (peer *Peer) RoutineSequential() {
	for work := range peer.queue.outbound {
		work.mutex.Lock()
		func() {
			peer.mutex.RLock()
			defer peer.mutex.RUnlock()
			if work.packet == nil {
				return
			}
			if peer.endpoint == nil {
				return
			}
			peer.device.conn.WriteToUDP(work.packet, peer.endpoint)
			peer.timer.sendKeepalive.Reset(peer.persistentKeepaliveInterval)
		}()
		work.mutex.Unlock()
	}
}
