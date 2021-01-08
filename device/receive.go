/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"golang.zx2c4.com/wireguard/conn"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	dropped int32
	sync.Mutex
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

func (elem *QueueInboundElement) Drop() {
	atomic.StoreInt32(&elem.dropped, AtomicTrue)
}

func (elem *QueueInboundElement) IsDropped() bool {
	return atomic.LoadInt32(&elem.dropped) == AtomicTrue
}

func (device *Device) addToInboundAndDecryptionQueues(inboundQueue chan *QueueInboundElement, decryptionQueue chan *QueueInboundElement, elem *QueueInboundElement) bool {
	select {
	case inboundQueue <- elem:
		select {
		case decryptionQueue <- elem:
			return true
		default:
			elem.Drop()
			elem.Unlock()
			return false
		}
	default:
		device.PutInboundElement(elem)
		return false
	}
}

func (device *Device) addToHandshakeQueue(queue chan QueueHandshakeElement, elem QueueHandshakeElement) bool {
	select {
	case queue <- elem:
		return true
	default:
		return false
	}
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Get() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Set(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(IP int, bind conn.Bind) {

	logDebug := device.log.Debug
	defer func() {
		logDebug.Println("Routine: receive incoming IPv" + strconv.Itoa(IP) + " - stopped")
		device.net.stopping.Done()
	}()

	logDebug.Println("Routine: receive incoming IPv" + strconv.Itoa(IP) + " - started")

	// receive datagrams until conn is closed

	buffer := device.GetMessageBuffer()

	var (
		err         error
		size        int
		endpoint    conn.Endpoint
		deathSpiral int
	)

	for {
		switch IP {
		case ipv4.Version:
			size, endpoint, err = bind.ReceiveIPv4(buffer[:])
		case ipv6.Version:
			size, endpoint, err = bind.ReceiveIPv6(buffer[:])
		default:
			panic("invalid IP version")
		}

		if err != nil {
			device.PutMessageBuffer(buffer)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Error.Printf("Failed to receive packet: %v", err)
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		if size < MinMessageSize {
			continue
		}

		// check size of packet

		packet := buffer[:size]
		msgType := binary.LittleEndian.Uint32(packet[:4])

		var okay bool

		switch msgType {

		// check if transport

		case MessageTransportType:

			// check size

			if len(packet) < MessageTransportSize {
				continue
			}

			// lookup key pair

			receiver := binary.LittleEndian.Uint32(
				packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
			)
			value := device.indexTable.Lookup(receiver)
			keypair := value.keypair
			if keypair == nil {
				continue
			}

			// check keypair expiry

			if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
				continue
			}

			// create work element
			peer := value.peer
			elem := device.GetInboundElement()
			elem.packet = packet
			elem.buffer = buffer
			elem.keypair = keypair
			elem.dropped = AtomicFalse
			elem.endpoint = endpoint
			elem.counter = 0
			elem.Mutex = sync.Mutex{}
			elem.Lock()

			// add to decryption queues

			peer.queue.RLock()
			if peer.isRunning.Get() {
				if device.addToInboundAndDecryptionQueues(peer.queue.inbound, device.queue.decryption, elem) {
					buffer = device.GetMessageBuffer()
				}
			} else {
				device.PutInboundElement(elem)
			}
			peer.queue.RUnlock()

			continue

		// otherwise it is a fixed size & handshake related packet

		case MessageInitiationType:
			okay = len(packet) == MessageInitiationSize

		case MessageResponseType:
			okay = len(packet) == MessageResponseSize

		case MessageCookieReplyType:
			okay = len(packet) == MessageCookieReplySize

		default:
			logDebug.Println("Received message with unknown type")
		}

		if okay {
			if (device.addToHandshakeQueue(
				device.queue.handshake,
				QueueHandshakeElement{
					msgType:  msgType,
					buffer:   buffer,
					packet:   packet,
					endpoint: endpoint,
				},
			)) {
				buffer = device.GetMessageBuffer()
			}
		}
	}
}

func (device *Device) RoutineDecryption() {

	var nonce [chacha20poly1305.NonceSize]byte

	logDebug := device.log.Debug
	defer func() {
		logDebug.Println("Routine: decryption worker - stopped")
		device.state.stopping.Done()
	}()
	logDebug.Println("Routine: decryption worker - started")

	for {
		select {
		case <-device.signals.stop:
			for {
				select {
				case elem, ok := <-device.queue.decryption:
					if ok {
						if !elem.IsDropped() {
							elem.Drop()
							device.PutMessageBuffer(elem.buffer)
						}
						elem.Unlock()
					}
				default:
					return
				}
			}

		case elem, ok := <-device.queue.decryption:

			if !ok {
				return
			}

			// check if dropped

			if elem.IsDropped() {
				continue
			}

			// split message into fields

			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer

			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.Drop()
				device.PutMessageBuffer(elem.buffer)
			}
			elem.Unlock()
		}
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake() {

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	var elem QueueHandshakeElement
	var ok bool

	defer func() {
		logDebug.Println("Routine: handshake worker - stopped")
		device.state.stopping.Done()
		if elem.buffer != nil {
			device.PutMessageBuffer(elem.buffer)
		}
	}()

	logDebug.Println("Routine: handshake worker - started")

	for {
		if elem.buffer != nil {
			device.PutMessageBuffer(elem.buffer)
			elem.buffer = nil
		}

		select {
		case elem, ok = <-device.queue.handshake:
		case <-device.signals.stop:
			return
		}

		if !ok {
			return
		}

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &reply)
			if err != nil {
				logDebug.Println("Failed to decode cookie reply")
				return
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				continue
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Get() {
				logDebug.Println("Receiving cookie response from ", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					logDebug.Println("Could not decrypt invalid cookie response")
				}
			}

			continue

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				logDebug.Println("Received packet with invalid mac1")
				continue
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					continue
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					continue
				}
			}

		default:
			logError.Println("Invalid packet ended up in the handshake queue")
			continue
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				logError.Println("Failed to decode initiation message")
				continue
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				logInfo.Println(
					"Received invalid initiation message from",
					elem.endpoint.DstToString(),
				)
				continue
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			logDebug.Println(peer, "- Received handshake initiation")
			atomic.AddUint64(&peer.stats.rxBytes, uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				logError.Println("Failed to decode response message")
				continue
			}

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				logInfo.Println(
					"Received invalid response message from",
					elem.endpoint.DstToString(),
				)
				continue
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			logDebug.Println(peer, "- Received handshake response")
			atomic.AddUint64(&peer.stats.rxBytes, uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				logError.Println(peer, "- Failed to derive keypair:", err)
				continue
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
			select {
			case peer.signals.newKeypairArrived <- struct{}{}:
			default:
			}
		}
	}
}

func (peer *Peer) RoutineSequentialReceiver() {

	device := peer.device
	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	var elem *QueueInboundElement

	defer func() {
		logDebug.Println(peer, "- Routine: sequential receiver - stopped")
		peer.routines.stopping.Done()
		if elem != nil {
			if !elem.IsDropped() {
				device.PutMessageBuffer(elem.buffer)
			}
			device.PutInboundElement(elem)
		}
	}()

	logDebug.Println(peer, "- Routine: sequential receiver - started")

	for {
		if elem != nil {
			if !elem.IsDropped() {
				device.PutMessageBuffer(elem.buffer)
			}
			device.PutInboundElement(elem)
			elem = nil
		}

		var elemOk bool
		select {
		case <-peer.routines.stop:
			return
		case elem, elemOk = <-peer.queue.inbound:
			if !elemOk {
				return
			}
		}

		// wait for decryption

		elem.Lock()

		if elem.IsDropped() {
			continue
		}

		// check for replay

		if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
			continue
		}

		// update endpoint
		peer.SetEndpointFromPacket(elem.endpoint)

		// check if using new keypair
		if peer.ReceivedWithKeypair(elem.keypair) {
			peer.timersHandshakeComplete()
			select {
			case peer.signals.newKeypairArrived <- struct{}{}:
			default:
			}
		}

		peer.keepKeyFreshReceiving()
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketReceived()
		atomic.AddUint64(&peer.stats.rxBytes, uint64(len(elem.packet)+MinMessageSize))

		// check for keepalive

		if len(elem.packet) == 0 {
			logDebug.Println(peer, "- Receiving keepalive packet")
			continue
		}
		peer.timersDataReceived()

		// verify source and strip padding

		switch elem.packet[0] >> 4 {
		case ipv4.Version:

			// strip padding

			if len(elem.packet) < ipv4.HeaderLen {
				continue
			}

			field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
			length := binary.BigEndian.Uint16(field)
			if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
				continue
			}

			elem.packet = elem.packet[:length]

			// verify IPv4 source

			src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
			if device.allowedips.LookupIPv4(src) != peer {
				logInfo.Println(
					"IPv4 packet with disallowed source address from",
					peer,
				)
				continue
			}

		case ipv6.Version:

			// strip padding

			if len(elem.packet) < ipv6.HeaderLen {
				continue
			}

			field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
			length := binary.BigEndian.Uint16(field)
			length += ipv6.HeaderLen
			if int(length) > len(elem.packet) {
				continue
			}

			elem.packet = elem.packet[:length]

			// verify IPv6 source

			src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
			if device.allowedips.LookupIPv6(src) != peer {
				logInfo.Println(
					"IPv6 packet with disallowed source address from",
					peer,
				)
				continue
			}

		default:
			logInfo.Println("Packet with invalid IP version from", peer)
			continue
		}

		// write to tun device

		offset := MessageTransportOffsetContent
		_, err := device.tun.device.Write(elem.buffer[:offset+len(elem.packet)], offset)
		if err != nil && !device.isClosed.Get() {
			logError.Println("Failed to write packet to TUN device:", err)
		}
		if len(peer.queue.inbound) == 0 {
			err := device.tun.device.Flush()
			if err != nil {
				peer.device.log.Error.Printf("Unable to flush packets: %v", err)
			}
		}
	}
}
