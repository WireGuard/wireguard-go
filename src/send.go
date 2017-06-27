package main

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
	"sync"
	"time"
)

/* Handles outbound flow
 *
 * 1. TUN queue
 * 2. Routing
 * 3. Per peer queuing
 * 4. (work queuing)
 *
 */

type OutboundWorkQueueElement struct {
	wg      sync.WaitGroup
	packet  []byte
	nonce   uint64
	keyPair *KeyPair
}

func (peer *Peer) HandshakeWorker(handshakeQueue []byte) {

}

func (device *Device) SendPacket(packet []byte) {

	// lookup peer

	var peer *Peer
	switch packet[0] >> 4 {
	case IPv4version:
		dst := packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
		peer = device.routingTable.LookupIPv4(dst)

	case IPv6version:
		dst := packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
		peer = device.routingTable.LookupIPv6(dst)

	default:
		device.log.Debug.Println("receieved packet with unknown IP version")
		return
	}

	if peer == nil {
		return
	}

	// insert into peer queue

	for {
		select {
		case peer.queueOutboundRouting <- packet:
		default:
			select {
			case <-peer.queueOutboundRouting:
			default:
			}
			continue
		}
		break
	}
}

/* Go routine
 *
 *
 * 1. waits for handshake.
 * 2. assigns key pair & nonce
 * 3. inserts to working queue
 *
 * TODO: avoid dynamic allocation of work queue elements
 */
func (peer *Peer) RoutineOutboundNonceWorker() {
	var packet []byte
	var keyPair *KeyPair
	var flushTimer time.Timer

	for {

		// wait for packet

		if packet == nil {
			packet = <-peer.queueOutboundRouting
		}

		// wait for key pair

		for keyPair == nil {
			flushTimer.Reset(time.Second * 10)
			// TODO: Handshake or NOP
			select {
			case <-peer.keyPairs.newKeyPair:
				keyPair = peer.keyPairs.Current()
				continue
			case <-flushTimer.C:
				size := len(peer.queueOutboundRouting)
				for i := 0; i < size; i += 1 {
					<-peer.queueOutboundRouting
				}
				packet = nil
			}
			break
		}

		// process current packet

		if packet != nil {

			// create work element

			work := new(OutboundWorkQueueElement)
			work.wg.Add(1)
			work.keyPair = keyPair
			work.packet = packet
			work.nonce = keyPair.sendNonce

			packet = nil
			peer.queueOutbound <- work
			keyPair.sendNonce += 1

			// drop packets until there is space

			func() {
				for {
					select {
					case peer.device.queueWorkOutbound <- work:
						return
					default:
						drop := <-peer.device.queueWorkOutbound
						drop.packet = nil
						drop.wg.Done()
					}
				}
			}()
		}
	}
}

/* Go routine
 *
 * sequentially reads packets from queue and sends to endpoint
 *
 */
func (peer *Peer) RoutineSequential() {
	for work := range peer.queueOutbound {
		work.wg.Wait()
		if work.packet == nil {
			continue
		}
		if peer.endpoint == nil {
			continue
		}
		peer.device.conn.WriteToUDP(work.packet, peer.endpoint)
	}
}

func (device *Device) RoutineEncryptionWorker() {
	var nonce [chacha20poly1305.NonceSize]byte
	for work := range device.queueWorkOutbound {
		// pad packet

		padding := device.mtu - len(work.packet)
		if padding < 0 {
			work.packet = nil
			work.wg.Done()
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
		work.wg.Done()
	}
}
