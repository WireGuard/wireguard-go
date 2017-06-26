package main

import (
	"net"
	"sync"
	"sync/atomic"
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
		device.logger.Println("unknown IP version")
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
func (peer *Peer) ConsumeOutboundPackets() {
	for {
		// wait for key pair
		keyPair := func() *KeyPair {
			peer.keyPairs.mutex.RLock()
			defer peer.keyPairs.mutex.RUnlock()
			return peer.keyPairs.current
		}()
		if keyPair == nil {
			if len(peer.queueOutboundRouting) > 0 {
				// TODO: start handshake
				<-peer.keyPairs.newKeyPair
			}
			continue
		}

		// assign packets key pair
		for {
			select {
			case <-peer.keyPairs.newKeyPair:
			default:
			case <-peer.keyPairs.newKeyPair:
			case packet := <-peer.queueOutboundRouting:

				// create new work element

				work := new(OutboundWorkQueueElement)
				work.wg.Add(1)
				work.keyPair = keyPair
				work.packet = packet
				work.nonce = atomic.AddUint64(&keyPair.sendNonce, 1) - 1

				peer.queueOutbound <- work

				// drop packets until there is room

				for {
					select {
					case peer.device.queueWorkOutbound <- work:
						break
					default:
						drop := <-peer.device.queueWorkOutbound
						drop.packet = nil
						drop.wg.Done()
					}
				}
			}
		}
	}
}

func (peer *Peer) RoutineSequential() {
	for work := range peer.queueOutbound {
		work.wg.Wait()
		if work.packet == nil {
			continue
		}
	}
}

func (device *Device) EncryptionWorker() {
	for {
		work := <-device.queueWorkOutbound

		func() {
			defer work.wg.Done()

			// pad packet
			padding := device.mtu - len(work.packet)
			if padding < 0 {
				work.packet = nil
				return
			}
			for n := 0; n < padding; n += 1 {
				work.packet = append(work.packet, 0) // TODO: gotta be a faster way
			}

			//

		}()
	}
}
