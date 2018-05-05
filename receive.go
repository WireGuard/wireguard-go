package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"strconv"
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
	dropped  int32
	mutex    sync.Mutex
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keyPair  *KeyPair
	endpoint Endpoint
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

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(IP int, bind Bind) {

	logDebug := device.log.Debug
	defer func() {
		logDebug.Println("Routine: receive incoming IPv" + strconv.Itoa(IP) + " - stopped")
	}()

	logDebug.Println("Routine: receive incoming IPv" + strconv.Itoa(IP) + " - starting")

	// receive datagrams until conn is closed

	buffer := device.GetMessageBuffer()

	var (
		err      error
		size     int
		endpoint Endpoint
	)

	for {

		// read next datagram

		switch IP {
		case ipv4.Version:
			size, endpoint, err = bind.ReceiveIPv4(buffer[:])
		case ipv6.Version:
			size, endpoint, err = bind.ReceiveIPv6(buffer[:])
		default:
			panic("invalid IP version")
		}

		if err != nil {
			return
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
				packet:   packet,
				buffer:   buffer,
				keyPair:  keyPair,
				dropped:  AtomicFalse,
				endpoint: endpoint,
			}
			elem.mutex.Lock()

			// add to decryption queues

			if peer.isRunning.Get() {
				device.addToDecryptionQueue(device.queue.decryption, elem)
				device.addToInboundQueue(peer.queue.inbound, elem)
				buffer = device.GetMessageBuffer()
			}

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

func (device *Device) RoutineDecryption() {

	var nonce [chacha20poly1305.NonceSize]byte

	logDebug := device.log.Debug
	defer func() {
		for {
			select {
			case elem, ok := <-device.queue.decryption:
				if ok {
					elem.Drop()
				}
			default:
				break
			}
		}
		logDebug.Println("Routine: decryption worker - stopped")
	}()
	logDebug.Println("Routine: decryption worker - started")

	for {
		select {
		case <-device.signal.stop.Wait():
			return

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

			// expand nonce

			nonce[0x4] = counter[0x0]
			nonce[0x5] = counter[0x1]
			nonce[0x6] = counter[0x2]
			nonce[0x7] = counter[0x3]

			nonce[0x8] = counter[0x4]
			nonce[0x9] = counter[0x5]
			nonce[0xa] = counter[0x6]
			nonce[0xb] = counter[0x7]

			// decrypt and release to consumer

			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			elem.packet, err = elem.keyPair.receive.Open(
				content[:0],
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

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake() {

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	defer func() {
		for {
			select {
			case <-device.queue.handshake:
			default:
				return
			}
		}
		logDebug.Println("Routine: handshake worker - stopped")
	}()

	logDebug.Println("Routine: handshake worker - started")

	var temp [MessageHandshakeSize]byte
	var elem QueueHandshakeElement
	var ok bool

	for {
		select {
		case elem, ok = <-device.queue.handshake:
		case <-device.signal.stop.Wait():
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

			entry := device.indices.Lookup(reply.Receiver)

			if entry.peer == nil {
				continue
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Get() {
				peer.mac.ConsumeReply(&reply)
			}

			continue

		case MessageInitiationType, MessageResponseType:

			// check mac fields and ratelimit

			if !device.mac.CheckMAC1(elem.packet) {
				logDebug.Println("Received packet with invalid mac1")
				continue
			}

			// endpoints destination address is the source of the datagram

			srcBytes := elem.endpoint.DstToBytes()

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.mac.CheckMAC2(elem.packet, srcBytes) {

					// construct cookie reply

					logDebug.Println(
						"Sending cookie reply to:",
						elem.endpoint.DstToString(),
					)

					sender := binary.LittleEndian.Uint32(elem.packet[4:8])
					reply, err := device.mac.CreateReply(elem.packet, sender, srcBytes)
					if err != nil {
						logError.Println("Failed to create cookie reply:", err)
						continue
					}

					// marshal and send reply

					writer := bytes.NewBuffer(temp[:0])
					binary.Write(writer, binary.LittleEndian, reply)
					device.net.bind.Send(writer.Bytes(), elem.endpoint)
					if err != nil {
						logDebug.Println("Failed to send cookie reply:", err)
					}
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

			peer.TimerAnyAuthenticatedPacketTraversal()
			peer.TimerAnyAuthenticatedPacketReceived()

			// update endpoint

			peer.mutex.Lock()
			peer.endpoint = elem.endpoint
			peer.mutex.Unlock()

			logDebug.Println(peer, ": Received handshake initiation")

			// create response

			response, err := device.CreateMessageResponse(peer)
			if err != nil {
				logError.Println("Failed to create response message:", err)
				continue
			}

			peer.TimerEphemeralKeyCreated()
			peer.NewKeyPair()

			logDebug.Println(peer, ": Creating handshake response")

			writer := bytes.NewBuffer(temp[:0])
			binary.Write(writer, binary.LittleEndian, response)
			packet := writer.Bytes()
			peer.mac.AddMacs(packet)

			// send response

			err = peer.SendBuffer(packet)
			if err == nil {
				peer.TimerAnyAuthenticatedPacketTraversal()
			} else {
				logError.Println(peer, ": Failed to send handshake response", err)
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

			// update endpoint

			peer.mutex.Lock()
			peer.endpoint = elem.endpoint
			peer.mutex.Unlock()

			logDebug.Println(peer, ": Received handshake response")

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

	defer func() {
		peer.routines.stopping.Done()
		logDebug.Println(peer, ": Routine: sequential receiver - stopped")
	}()

	logDebug.Println(peer, ": Routine: sequential receiver - started")

	peer.routines.starting.Done()

	for {

		select {

		case <-peer.routines.stop.Wait():
			return

		case elem, ok := <-peer.queue.inbound:

			if !ok {
				return
			}

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

			// update endpoint

			peer.mutex.Lock()
			peer.endpoint = elem.endpoint
			peer.mutex.Unlock()

			// check for keep-alive

			if len(elem.packet) == 0 {
				logDebug.Println(peer, ": Received keep-alive")
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
				if device.routing.table.LookupIPv4(src) != peer {
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
				if device.routing.table.LookupIPv6(src) != peer {
					logInfo.Println(
						peer,
						"sent packet with disallowed IPv6 source",
					)
					continue
				}

			default:
				logInfo.Println("Packet with invalid IP version from", peer)
				continue
			}

			// write to tun device

			offset := MessageTransportOffsetContent
			atomic.AddUint64(&peer.stats.rxBytes, uint64(len(elem.packet)))
			_, err := device.tun.device.Write(
				elem.buffer[:offset+len(elem.packet)],
				offset)
			device.PutMessageBuffer(elem.buffer)
			if err != nil {
				logError.Println("Failed to write packet to TUN device:", err)
			}
		}
	}
}
