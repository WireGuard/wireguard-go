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

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	dropped int32
	mutex   sync.Mutex
	buffer  *[MaxMessageSize]byte
	packet  []byte
	counter uint64
	keyPair *KeyPair
}

func (elem *QueueInboundElement) Drop() {
	atomic.StoreInt32(&elem.dropped, AtomicTrue)
}

func (elem *QueueInboundElement) IsDropped() bool {
	return atomic.LoadInt32(&elem.dropped) == AtomicTrue
}

func (device *Device) addToInboundQueue(
	queue chan *QueueInboundElement,
	element *QueueInboundElement,
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

func (device *Device) addToDecryptionQueue(
	queue chan *QueueInboundElement,
	element *QueueInboundElement,
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

func (device *Device) addToHandshakeQueue(
	queue chan QueueHandshakeElement,
	element QueueHandshakeElement,
) {
	for {
		select {
		case queue <- element:
			return
		default:
			select {
			case elem := <-queue:
				device.PutMessageBuffer(elem.buffer)
			default:
			}
		}
	}
}

func (device *Device) RoutineReceiveIncomming(IPVersion int) {

	logDebug := device.log.Debug
	logDebug.Println("Routine, receive incomming, IP version:", IPVersion)

	for {

		// wait for bind

		logDebug.Println("Waiting for UDP socket, IP version:", IPVersion)

		device.net.update.Wait()
		device.net.mutex.RLock()
		bind := device.net.bind
		device.net.mutex.RUnlock()
		if bind == nil {
			continue
		}

		// receive datagrams until conn is closed

		buffer := device.GetMessageBuffer()

		var size int
		var err error

		for {

			// read next datagram

			var endpoint Endpoint

			switch IPVersion {
			case ipv4.Version:
				size, err = bind.ReceiveIPv4(buffer[:], &endpoint)
			case ipv6.Version:
				size, err = bind.ReceiveIPv6(buffer[:], &endpoint)
			default:
				return
			}

			if err != nil {
				break
			}

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

				if len(packet) < MessageTransportType {
					continue
				}

				// lookup key pair

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indices.Lookup(receiver)
				keyPair := value.keyPair
				if keyPair == nil {
					continue
				}

				// check key-pair expiry

				if keyPair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}

				// create work element

				peer := value.peer
				elem := &QueueInboundElement{
					packet:  packet,
					buffer:  buffer,
					keyPair: keyPair,
					dropped: AtomicFalse,
				}
				elem.mutex.Lock()

				// add to decryption queues

				device.addToDecryptionQueue(device.queue.decryption, elem)
				device.addToInboundQueue(peer.queue.inbound, elem)
				buffer = device.GetMessageBuffer()
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				okay = len(packet) == MessageInitiationSize

			case MessageResponseType:
				okay = len(packet) == MessageResponseSize

			case MessageCookieReplyType:
				okay = len(packet) == MessageCookieReplySize
			}

			if okay {
				device.addToHandshakeQueue(
					device.queue.handshake,
					QueueHandshakeElement{
						msgType:  msgType,
						buffer:   buffer,
						packet:   packet,
						endpoint: endpoint,
					},
				)
				buffer = device.GetMessageBuffer()
			}
		}
	}
}

func (device *Device) RoutineDecryption() {

	var nonce [chacha20poly1305.NonceSize]byte

	logDebug := device.log.Debug
	logDebug.Println("Routine, decryption, started for device")

	for {
		select {
		case <-device.signal.stop:
			logDebug.Println("Routine, decryption worker, stopped")
			return

		case elem := <-device.queue.decryption:

			// check if dropped

			if elem.IsDropped() {
				continue
			}

			// split message into fields

			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer

			var err error
			copy(nonce[4:], counter)
			elem.counter = binary.LittleEndian.Uint64(counter)
			elem.packet, err = elem.keyPair.receive.Open(
				elem.buffer[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.Drop()
			}
			elem.mutex.Unlock()
		}
	}
}

/* Handles incomming packets related to handshake
 */
func (device *Device) RoutineHandshake() {

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug
	logDebug.Println("Routine, handshake routine, started for device")

	var temp [MessageHandshakeSize]byte
	var elem QueueHandshakeElement

	for {
		select {
		case elem = <-device.queue.handshake:
		case <-device.signal.stop:
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

			// lookup peer and consume response

			entry := device.indices.Lookup(reply.Receiver)
			if entry.peer == nil {
				return
			}
			entry.peer.mac.ConsumeReply(&reply)
			continue

		case MessageInitiationType, MessageResponseType:

			// check mac fields and ratelimit

			if !device.mac.CheckMAC1(elem.packet) {
				logDebug.Println("Received packet with invalid mac1")
				return
			}

			srcBytes := elem.endpoint.SrcToBytes()
			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.mac.CheckMAC2(elem.packet, srcBytes) {

					// construct cookie reply

					logDebug.Println("Sending cookie reply to:", elem.endpoint.SrcToString())
					sender := binary.LittleEndian.Uint32(elem.packet[4:8]) // "sender" always follows "type"
					reply, err := device.mac.CreateReply(elem.packet, sender, srcBytes)
					if err != nil {
						logError.Println("Failed to create cookie reply:", err)
						return
					}

					// marshal and send reply

					writer := bytes.NewBuffer(temp[:0])
					binary.Write(writer, binary.LittleEndian, reply)
					device.net.bind.Send(
						writer.Bytes(),
						&elem.endpoint,
					)
					if err != nil {
						logDebug.Println("Failed to send cookie reply:", err)
					}
					continue
				}

				// check ratelimiter

				if !device.ratelimiter.Allow(elem.endpoint.DstIP()) {
					continue
				}
			}

		default:
			logError.Println("Invalid packet ended up in the handshake queue")
			continue
		}

		// handle handshake initation/response content

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
					"Recieved invalid initiation message from",
					elem.endpoint.DstToString(),
				)
				continue
			}

			// update timers

			peer.TimerAnyAuthenticatedPacketTraversal()
			peer.TimerAnyAuthenticatedPacketReceived()

			// update endpoint
			// TODO: Discover destination address also, only update on change

			peer.mutex.Lock()
			peer.endpoint.set = true
			peer.endpoint.value = elem.endpoint
			peer.mutex.Unlock()

			// create response

			response, err := device.CreateMessageResponse(peer)
			if err != nil {
				logError.Println("Failed to create response message:", err)
				continue
			}

			peer.TimerEphemeralKeyCreated()
			peer.NewKeyPair()

			logDebug.Println("Creating response message for", peer.String())

			writer := bytes.NewBuffer(temp[:0])
			binary.Write(writer, binary.LittleEndian, response)
			packet := writer.Bytes()
			peer.mac.AddMacs(packet)

			// send response

			err = peer.SendBuffer(packet)
			if err == nil {
				peer.TimerAnyAuthenticatedPacketTraversal()
			} else {
				logError.Println("Failed to send response to:", peer.String(), err)
			}

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
					"Recieved invalid response message from",
					elem.endpoint.DstToString(),
				)
				continue
			}

			logDebug.Println("Received handshake initation from", peer)

			peer.TimerEphemeralKeyCreated()

			// update timers

			peer.TimerAnyAuthenticatedPacketTraversal()
			peer.TimerAnyAuthenticatedPacketReceived()
			peer.TimerHandshakeComplete()

			// derive key-pair

			peer.NewKeyPair()
			peer.SendKeepAlive()
		}
	}
}

func (peer *Peer) RoutineSequentialReceiver() {

	device := peer.device

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug
	logDebug.Println("Routine, sequential receiver, started for peer", peer.id)

	for {

		select {
		case <-peer.signal.stop:
			logDebug.Println("Routine, sequential receiver, stopped for peer", peer.id)
			return

		case elem := <-peer.queue.inbound:

			// wait for decryption

			elem.mutex.Lock()
			if elem.IsDropped() {
				continue
			}

			// check for replay

			if !elem.keyPair.replayFilter.ValidateCounter(elem.counter) {
				continue
			}

			peer.TimerAnyAuthenticatedPacketTraversal()
			peer.TimerAnyAuthenticatedPacketReceived()
			peer.KeepKeyFreshReceiving()

			// check if using new key-pair

			kp := &peer.keyPairs
			kp.mutex.Lock()
			if kp.next == elem.keyPair {
				peer.TimerHandshakeComplete()
				if kp.previous != nil {
					device.DeleteKeyPair(kp.previous)
				}
				kp.previous = kp.current
				kp.current = kp.next
				kp.next = nil
			}
			kp.mutex.Unlock()

			// check for keep-alive

			if len(elem.packet) == 0 {
				logDebug.Println("Received keep-alive from", peer.String())
				continue
			}
			peer.TimerDataReceived()

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
				if device.routingTable.LookupIPv4(src) != peer {
					logInfo.Println("Packet with unallowed source IP from", peer.String())
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
				if device.routingTable.LookupIPv6(src) != peer {
					logInfo.Println("Packet with unallowed source IP from", peer.String())
					continue
				}

			default:
				logInfo.Println("Packet with invalid IP version from", peer.String())
				continue
			}

			// write to tun

			atomic.AddUint64(&peer.stats.rxBytes, uint64(len(elem.packet)))
			_, err := device.tun.device.Write(elem.packet)
			device.PutMessageBuffer(elem.buffer)
			if err != nil {
				logError.Println("Failed to write packet to TUN device:", err)
			}
		}
	}
}
