package main

import (
	"errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"sync"
	"time"
)

const (
	HandshakeZeroed = iota
	HandshakeInitiationCreated
	HandshakeInitiationConsumed
	HandshakeResponseCreated
	HandshakeResponseConsumed
)

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148
	MessageResponseSize        = 92
	MessageCookieReplySize     = 64
	MessageTransportHeaderSize = 16
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize // size of empty transport
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [TAI64NSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [24]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte
}

type Handshake struct {
	state                   int
	mutex                   sync.RWMutex
	hash                    [blake2s.Size]byte       // hash value
	chainKey                [blake2s.Size]byte       // chain key
	presharedKey            NoiseSymmetricKey        // psk
	localEphemeral          NoisePrivateKey          // ephemeral secret key
	localIndex              uint32                   // used to clear hash-table
	remoteIndex             uint32                   // index for sending
	remoteStatic            NoisePublicKey           // long term key
	remoteEphemeral         NoisePublicKey           // ephemeral public key
	precomputedStaticStatic [NoisePublicKeySize]byte // precomputed shared secret
	lastTimestamp           TAI64N
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(c [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	return KDF1(c[:], data)
}

func mixHash(h [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	return blake2s.Sum256(append(h[:], data...))
}

func (h *Handshake) mixHash(data []byte) {
	h.hash = mixHash(h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	h.chainKey = mixKey(h.chainKey, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	InitialHash = mixHash(InitialChainKey, []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key

	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	// assign index

	device.indices.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indices.NewIndex(peer)

	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.publicKey(),
		Sender:    handshake.localIndex,
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key

	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
		handshake.chainKey, key = KDF2(handshake.chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Static[:0], ZeroNonce[:], device.publicKey[:], handshake.hash[:])
	}()
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp

	timestamp := Timestamp()
	func() {
		var key [chacha20poly1305.KeySize]byte
		handshake.chainKey, key = KDF2(
			handshake.chainKey[:],
			handshake.precomputedStaticStatic[:],
		)
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])
	}()

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = HandshakeInitiationCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	if msg.Type != MessageInitiationType {
		return nil
	}

	hash := mixHash(InitialHash, device.publicKey[:])
	hash = mixHash(hash, msg.Ephemeral[:])
	chainKey := mixKey(InitialChainKey, msg.Ephemeral[:])

	// decrypt static key

	var err error
	var peerPK NoisePublicKey
	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := device.privateKey.sharedSecret(msg.Ephemeral)
		chainKey, key = KDF2(chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	}()
	if err != nil {
		return nil
	}
	hash = mixHash(hash, msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil {
		return nil
	}
	handshake := &peer.handshake

	// verify identity

	var timestamp TAI64N
	ok := func() bool {

		// read lock handshake

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		// decrypt timestamp

		func() {
			var key [chacha20poly1305.KeySize]byte
			chainKey, key = KDF2(
				chainKey[:],
				handshake.precomputedStaticStatic[:],
			)
			aead, _ := chacha20poly1305.New(key[:])
			_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
		}()
		if err != nil {
			return false
		}
		hash = mixHash(hash, msg.Timestamp[:])

		// TODO: check for flood attack

		// check for replay attack

		return timestamp.After(handshake.lastTimestamp)
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	handshake.lastTimestamp = timestamp
	handshake.state = HandshakeInitiationConsumed

	handshake.mutex.Unlock()

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != HandshakeInitiationConsumed {
		return nil, errors.New("handshake initation must be consumed first")
	}

	// assign index

	var err error
	device.indices.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indices.NewIndex(peer)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	func() {
		ss := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
		handshake.mixKey(ss[:])
		ss = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
		handshake.mixKey(ss[:])
	}()

	// add preshared key (psk)

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	handshake.chainKey, tau, key = KDF3(handshake.chainKey[:], handshake.presharedKey[:])
	handshake.mixHash(tau[:])

	func() {
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
		handshake.mixHash(msg.Empty[:])
	}()

	handshake.state = HandshakeResponseCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by reciever

	lookup := device.indices.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {

		// read lock handshake

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != HandshakeInitiationCreated {
			return false
		}

		// finish 3-way DH

		hash = mixHash(handshake.hash, msg.Ephemeral[:])
		chainKey = mixKey(handshake.chainKey, msg.Ephemeral[:])

		func() {
			ss := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
			chainKey = mixKey(chainKey, ss[:])
			ss = device.privateKey.sharedSecret(msg.Ephemeral)
			chainKey = mixKey(chainKey, ss[:])
		}()

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		chainKey, tau, key = KDF3(chainKey[:], handshake.presharedKey[:])
		hash = mixHash(hash, tau[:])

		// authenticate

		aead, _ := chacha20poly1305.New(key[:])
		_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			device.log.Debug.Println("failed to open")
			return false
		}
		hash = mixHash(hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = HandshakeResponseConsumed

	handshake.mutex.Unlock()

	return lookup.peer
}

func (peer *Peer) NewKeyPair() *KeyPair {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == HandshakeResponseConsumed {
		sendKey, recvKey = KDF2(handshake.chainKey[:], nil)
		isInitiator = true
	} else if handshake.state == HandshakeResponseCreated {
		recvKey, sendKey = KDF2(handshake.chainKey[:], nil)
		isInitiator = false
	} else {
		return nil
	}

	// zero handshake

	handshake.chainKey = [blake2s.Size]byte{}
	handshake.localEphemeral = NoisePrivateKey{}
	peer.handshake.state = HandshakeZeroed

	// create AEAD instances

	keyPair := new(KeyPair)
	keyPair.send, _ = chacha20poly1305.New(sendKey[:])
	keyPair.receive, _ = chacha20poly1305.New(recvKey[:])
	keyPair.sendNonce = 0
	keyPair.created = time.Now()
	keyPair.isInitiator = isInitiator
	keyPair.localIndex = peer.handshake.localIndex
	keyPair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	peer.device.indices.Insert(handshake.localIndex, IndexTableEntry{
		peer:      peer,
		keyPair:   keyPair,
		handshake: nil,
	})
	handshake.localIndex = 0

	// TODO: start timer for keypair (clearing)

	// rotate key pairs

	kp := &peer.keyPairs
	func() {
		kp.mutex.Lock()
		defer kp.mutex.Unlock()
		if isInitiator {
			if kp.previous != nil {
				kp.previous.send = nil
				kp.previous.receive = nil
				peer.device.indices.Delete(kp.previous.localIndex)
			}
			kp.previous = kp.current
			kp.current = keyPair
			sendSignal(peer.signal.newKeyPair)
		} else {
			kp.next = keyPair
		}
	}()

	return keyPair
}
