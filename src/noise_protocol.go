package main

import (
	"errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"sync"
)

const (
	HandshakeReset = iota
	HandshakeInitialCreated
	HandshakeInitialConsumed
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
	MessageInitalType         = 1
	MessageResponseType       = 2
	MessageCookieResponseType = 3
	MessageTransportType      = 4
)

type MessageInital struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [TAI64NSize + poly1305.TagSize]byte
	Mac1      [blake2s.Size128]byte
	Mac2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Reciever  uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	Mac1      [blake2s.Size128]byte
	Mac2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Reciever uint32
	Counter  uint64
	Content  []byte
}

type Handshake struct {
	state                   int
	mutex                   sync.Mutex
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
	ZeroNonce      [chacha20poly1305.NonceSize]byte
	InitalChainKey [blake2s.Size]byte
	InitalHash     [blake2s.Size]byte
)

func init() {
	InitalChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	InitalHash = blake2s.Sum256(append(InitalChainKey[:], []byte(WGIdentifier)...))
}

func addToChainKey(c [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	return KDF1(c[:], data)
}

func addToHash(h [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	return blake2s.Sum256(append(h[:], data...))
}

func (h *Handshake) addToHash(data []byte) {
	h.hash = addToHash(h.hash, data)
}

func (h *Handshake) addToChainKey(data []byte) {
	h.chainKey = addToChainKey(h.chainKey, data)
}

func (device *Device) CreateMessageInitial(peer *Peer) (*MessageInital, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key

	var err error
	handshake.chainKey = InitalChainKey
	handshake.hash = addToHash(InitalHash, handshake.remoteStatic[:])
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	// assign index

	var msg MessageInital

	msg.Type = MessageInitalType
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.localIndex, err = device.indices.NewIndex(peer)

	if err != nil {
		return nil, err
	}

	msg.Sender = handshake.localIndex
	handshake.addToChainKey(msg.Ephemeral[:])
	handshake.addToHash(msg.Ephemeral[:])

	// encrypt identity key

	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
		handshake.chainKey, key = KDF2(handshake.chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Static[:0], ZeroNonce[:], device.publicKey[:], handshake.hash[:])
	}()
	handshake.addToHash(msg.Static[:])

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

	handshake.addToHash(msg.Timestamp[:])
	handshake.state = HandshakeInitialCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageInitial(msg *MessageInital) *Peer {
	if msg.Type != MessageInitalType {
		panic(errors.New("bug: invalid inital message type"))
	}

	hash := addToHash(InitalHash, device.publicKey[:])
	hash = addToHash(hash, msg.Ephemeral[:])
	chainKey := addToChainKey(InitalChainKey, msg.Ephemeral[:])

	// decrypt identity key

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
	hash = addToHash(hash, msg.Static[:])

	// find peer

	peer := device.LookupPeer(peerPK)
	if peer == nil {
		return nil
	}
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// decrypt timestamp

	var timestamp TAI64N
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
		return nil
	}
	hash = addToHash(hash, msg.Timestamp[:])

	// check for replay attack

	if !timestamp.After(handshake.lastTimestamp) {
		return nil
	}

	// check for flood attack

	// update handshake state

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	handshake.lastTimestamp = timestamp
	handshake.state = HandshakeInitialConsumed
	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != HandshakeInitialConsumed {
		panic(errors.New("bug: handshake initation must be consumed first"))
	}

	// assign index

	var err error
	handshake.localIndex, err = device.indices.NewIndex(peer)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Reciever = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.addToHash(msg.Ephemeral[:])

	func() {
		ss := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
		handshake.addToChainKey(ss[:])
		ss = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
		handshake.addToChainKey(ss[:])
	}()

	// add preshared key (psk)

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	handshake.chainKey, tau, key = KDF3(handshake.chainKey[:], handshake.presharedKey[:])
	handshake.addToHash(tau[:])

	func() {
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
		handshake.addToHash(msg.Empty[:])
	}()

	handshake.state = HandshakeResponseCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		panic(errors.New("bug: invalid message type"))
	}

	// lookup handshake by reciever

	peer := device.indices.LookupHandshake(msg.Reciever)
	if peer == nil {
		return nil
	}
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()
	if handshake.state != HandshakeInitialCreated {
		return nil
	}

	// finish 3-way DH

	hash := addToHash(handshake.hash, msg.Ephemeral[:])
	chainKey := handshake.chainKey

	func() {
		ss := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
		chainKey = addToChainKey(chainKey, ss[:])
		ss = device.privateKey.sharedSecret(msg.Ephemeral)
		chainKey = addToChainKey(chainKey, ss[:])
	}()

	// add preshared key (psk)

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	chainKey, tau, key = KDF3(chainKey[:], handshake.presharedKey[:])
	hash = addToHash(hash, tau[:])

	// authenticate

	aead, _ := chacha20poly1305.New(key[:])
	_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
	if err != nil {
		return nil
	}
	hash = addToHash(hash, msg.Empty[:])

	// update handshake state

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = HandshakeResponseConsumed

	return peer
}

func (peer *Peer) NewKeyPair() *KeyPair {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == HandshakeResponseConsumed {
		sendKey, recvKey = KDF2(handshake.chainKey[:], nil)
	} else if handshake.state == HandshakeResponseCreated {
		recvKey, sendKey = KDF2(handshake.chainKey[:], nil)
	} else {
		return nil
	}

	// create AEAD instances

	var keyPair KeyPair
	keyPair.send, _ = chacha20poly1305.New(sendKey[:])
	keyPair.recv, _ = chacha20poly1305.New(recvKey[:])
	keyPair.sendNonce = 0
	keyPair.recvNonce = 0

	peer.handshake.state = HandshakeReset

	return &keyPair
}
