package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ElementStateOkay = iota
	ElementStateDropped
)

type QueueHandshakeElement struct {
	msgType uint32
	packet  []byte
	source  *net.UDPAddr
}

type QueueInboundElement struct {
	state   uint32
	mutex   sync.Mutex
	packet  []byte
	counter uint64
	keyPair *KeyPair
}

func (elem *QueueInboundElement) Drop() {
	atomic.StoreUint32(&elem.state, ElementStateDropped)
	elem.mutex.Unlock()
}

func (device *Device) RoutineReceiveIncomming() {
	var packet []byte

	debugLog := device.log.Debug
	debugLog.Println("Routine, receive incomming, started")

	errorLog := device.log.Error

	for {

		// check if stopped

		select {
		case <-device.signal.stop:
			return
		default:
		}

		// read next datagram

		if packet == nil {
			packet = make([]byte, 1<<16)
		}

		device.net.mutex.RLock()
		conn := device.net.conn
		device.net.mutex.RUnlock()

		conn.SetReadDeadline(time.Now().Add(time.Second))

		size, raddr, err := conn.ReadFromUDP(packet)
		if err != nil {
			continue
		}
		if size < MinMessageSize {
			continue
		}

		// handle packet

		packet = packet[:size]
		msgType := binary.LittleEndian.Uint32(packet[:4])

		func() {
			switch msgType {

			case MessageInitiationType, MessageResponseType:

				// verify mac1

				if !device.mac.CheckMAC1(packet) {
					debugLog.Println("Received packet with invalid mac1")
					return
				}

				// check if busy, TODO: refine definition of "busy"

				busy := len(device.queue.handshake) > QueueHandshakeBusySize
				if busy && !device.mac.CheckMAC2(packet, raddr) {
					sender := binary.LittleEndian.Uint32(packet[4:8]) // "sender" follows "type"
					reply, err := device.CreateMessageCookieReply(packet, sender, raddr)
					if err != nil {
						errorLog.Println("Failed to create cookie reply:", err)
						return
					}
					writer := bytes.NewBuffer(packet[:0])
					binary.Write(writer, binary.LittleEndian, reply)
					packet = writer.Bytes()
					_, err = device.net.conn.WriteToUDP(packet, raddr)
					if err != nil {
						debugLog.Println("Failed to send cookie reply:", err)
					}
					return
				}

				// add to handshake queue

				device.queue.handshake <- QueueHandshakeElement{
					msgType: msgType,
					packet:  packet,
					source:  raddr,
				}

			case MessageCookieReplyType:

				// verify and update peer cookie state

				if len(packet) != MessageCookieReplySize {
					return
				}

				var reply MessageCookieReply
				reader := bytes.NewReader(packet)
				err := binary.Read(reader, binary.LittleEndian, &reply)
				if err != nil {
					debugLog.Println("Failed to decode cookie reply")
					return
				}
				device.ConsumeMessageCookieReply(&reply)

			case MessageTransportType:

				debugLog.Println("DEBUG: Got transport")

				// lookup key pair

				if len(packet) < MessageTransportSize {
					return
				}

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indices.Lookup(receiver)
				keyPair := value.keyPair
				if keyPair == nil {
					return
				}

				// check key-pair expiry

				if keyPair.created.Add(RejectAfterTime).Before(time.Now()) {
					return
				}

				// add to peer queue

				peer := value.peer
				work := new(QueueInboundElement)
				work.packet = packet
				work.keyPair = keyPair
				work.state = ElementStateOkay
				work.mutex.Lock()

				// add to parallel decryption queue

				func() {
					for {
						select {
						case device.queue.decryption <- work:
							return
						default:
							select {
							case elem := <-device.queue.decryption:
								elem.Drop()
							default:
							}
						}
					}
				}()

				// add to sequential inbound queue

				func() {
					for {
						select {
						case peer.queue.inbound <- work:
							break
						default:
							select {
							case elem := <-peer.queue.inbound:
								elem.Drop()
							default:
							}
						}
					}
				}()

			default:
				// unknown message type
			}
		}()
	}
}

func (device *Device) RoutineDecryption() {
	var elem *QueueInboundElement
	var nonce [chacha20poly1305.NonceSize]byte

	for {
		select {
		case elem = <-device.queue.decryption:
		case <-device.signal.stop:
			return
		}

		// check if dropped

		state := atomic.LoadUint32(&elem.state)
		if state != ElementStateOkay {
			continue
		}

		// split message into fields

		counter := binary.LittleEndian.Uint64(
			elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent],
		)
		content := elem.packet[MessageTransportOffsetContent:]

		// decrypt with key-pair

		var err error
		binary.LittleEndian.PutUint64(nonce[4:], counter)
		elem.packet, err = elem.keyPair.recv.Open(elem.packet[:0], nonce[:], content, nil)
		if err != nil {
			elem.Drop()
			continue
		}

		// release to consumer

		elem.counter = counter
		elem.mutex.Unlock()
	}
}

/* Handles incomming packets related to handshake
 *
 *
 */
func (device *Device) RoutineHandshake() {

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	var elem QueueHandshakeElement

	for {
		select {
		case elem = <-device.queue.handshake:
		case <-device.signal.stop:
			return
		}

		func() {

			switch elem.msgType {
			case MessageInitiationType:

				// unmarshal

				if len(elem.packet) != MessageInitiationSize {
					return
				}

				var msg MessageInitiation
				reader := bytes.NewReader(elem.packet)
				err := binary.Read(reader, binary.LittleEndian, &msg)
				if err != nil {
					logError.Println("Failed to decode initiation message")
					return
				}

				// consume initiation

				peer := device.ConsumeMessageInitiation(&msg)
				if peer == nil {
					logInfo.Println(
						"Recieved invalid initiation message from",
						elem.source.IP.String(),
						elem.source.Port,
					)
					return
				}
				logDebug.Println("Recieved valid initiation message for peer", peer.id)

			case MessageResponseType:

				// unmarshal

				if len(elem.packet) != MessageResponseSize {
					return
				}

				var msg MessageResponse
				reader := bytes.NewReader(elem.packet)
				err := binary.Read(reader, binary.LittleEndian, &msg)
				if err != nil {
					logError.Println("Failed to decode response message")
					return
				}

				// consume response

				peer := device.ConsumeMessageResponse(&msg)
				if peer == nil {
					logInfo.Println(
						"Recieved invalid response message from",
						elem.source.IP.String(),
						elem.source.Port,
					)
					return
				}
				sendSignal(peer.signal.handshakeCompleted)
				logDebug.Println("Recieved valid response message for peer", peer.id)
				peer.NewKeyPair()
				peer.SendKeepAlive()

			default:
				device.log.Error.Println("Invalid message type in handshake queue")
			}

		}()
	}
}

func (peer *Peer) RoutineSequentialReceiver() {
	var elem *QueueInboundElement

	device := peer.device
	logDebug := device.log.Debug

	logDebug.Println("Routine, sequential receiver, started for peer", peer.id)

	for {
		// wait for decryption

		select {
		case <-peer.signal.stop:
			return
		case elem = <-peer.queue.inbound:
		}
		elem.mutex.Lock()

		// check if dropped

		logDebug.Println("MESSSAGE:", elem)

		state := atomic.LoadUint32(&elem.state)
		if state != ElementStateOkay {
			continue
		}

		// check for replay

		// check for keep-alive

		if len(elem.packet) == 0 {
			continue
		}

		// insert into inbound TUN queue

		device.queue.inbound <- elem.packet
	}

}

func (device *Device) RoutineWriteToTUN(tun TUNDevice) {
	for {
		var packet []byte

		select {
		case <-device.signal.stop:
		case packet = <-device.queue.inbound:
		}

		device.log.Debug.Println("GOT:", packet)

		size, err := tun.Write(packet)
		device.log.Debug.Println("DEBUG:", size, err)
		if err != nil {

		}
	}
}
