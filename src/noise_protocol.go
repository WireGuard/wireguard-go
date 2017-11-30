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
	MessageInitiationSize      = 148                                           // size of handshake initation message
	MessageResponseSize        = 92                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceeding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake releated message
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
	state                     int
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte       // hash value
	chainKey                  [blake2s.Size]byte       // chain key
	presharedKey              NoiseSymmetricKey        // psk
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key
	remoteEphemeral           NoisePublicKey           // ephemeral public key
	precomputedStaticStatic   [NoisePublicKeySize]byte // precomputed shared secret
	lastTimestamp             TAI64N
	lastInitiationConsumption time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hsh, _ := blake2s.New256(nil)
	hsh.Write(h[:])
	hsh.Write(data)
	hsh.Sum(dst[:0])
	hsh.Reset()
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errors.New("Static shared secret is zero")
	}

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
		KDF2(
			&handshake.chainKey,
			&key,
			handshake.chainKey[:],
			ss[:],
		)
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Static[:0], ZeroNonce[:], device.publicKey[:], handshake.hash[:])
	}()
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp

	timestamp := Timestamp()
	func() {
		var key [chacha20poly1305.KeySize]byte
		KDF2(
			&handshake.chainKey,
			&key,
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

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	mixHash(&hash, &InitialHash, device.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key

	var err error
	var peerPK NoisePublicKey
	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := device.privateKey.sharedSecret(msg.Ephemeral)
		KDF2(&chainKey, &key, chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	}()
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil {
		return nil
	}

	handshake := &peer.handshake
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil
	}

	// verify identity

	var timestamp TAI64N
	var key [chacha20poly1305.KeySize]byte

	handshake.mutex.RLock()
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	var ok bool
	ok = timestamp.After(handshake.lastTimestamp)
	ok = ok && time.Now().Sub(handshake.lastInitiationConsumption) > HandshakeInitationRate
	handshake.mutex.RUnlock()
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
	handshake.lastInitiationConsumption = time.Now()
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

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

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

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		func() {
			ss := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		func() {
			ss := device.privateKey.sharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate

		aead, _ := chacha20poly1305.New(key[:])
		_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			device.log.Debug.Println("failed to open")
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
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

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new key-pair from the current handshake state
 *
 */
func (peer *Peer) NewKeyPair() *KeyPair {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == HandshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == HandshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return nil
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = HandshakeZeroed

	// create AEAD instances

	keyPair := new(KeyPair)
	keyPair.send, _ = chacha20poly1305.New(sendKey[:])
	keyPair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keyPair.created = time.Now()
	keyPair.sendNonce = 0
	keyPair.replayFilter.Init()
	keyPair.isInitiator = isInitiator
	keyPair.localIndex = peer.handshake.localIndex
	keyPair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indices.Insert(
		handshake.localIndex,
		IndexTableEntry{
			peer:      peer,
			keyPair:   keyPair,
			handshake: nil,
		},
	)
	handshake.localIndex = 0

	// rotate key pairs

	kp := &peer.keyPairs
	kp.mutex.Lock()

	if isInitiator {
		if kp.previous != nil {
			device.DeleteKeyPair(kp.previous)
			kp.previous = nil
		}

		if kp.next != nil {
			kp.previous = kp.next
			kp.next = keyPair
		} else {
			kp.previous = kp.current
			kp.current = keyPair
			peer.signal.newKeyPair.Send()
		}

	} else {
		kp.next = keyPair
		kp.previous = nil
	}
	kp.mutex.Unlock()

	return keyPair
}
