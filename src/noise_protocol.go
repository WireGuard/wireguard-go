package main

import (
	"errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"sync"
)

const (
	HandshakeInitialCreated = iota
	HandshakeInitialConsumed
	HandshakeResponseCreated
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
	lock         sync.Mutex
	state        int
	chainKey     [blake2s.Size]byte // chain key
	hash         [blake2s.Size]byte // hash value
	staticStatic NoisePublicKey     // precomputed DH(S_i, S_r)
	ephemeral    NoisePrivateKey    // ephemeral secret key
	remoteIndex  uint32             // index for sending
	device       *Device
	peer         *Peer
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

func (h *Handshake) Precompute() {
	h.staticStatic = h.device.privateKey.sharedSecret(h.peer.publicKey)
}

func (h *Handshake) ConsumeMessageResponse(msg *MessageResponse) {

}

func (h *Handshake) addHash(data []byte) {
	h.hash = addToHash(h.hash, data)
}

func (h *Handshake) addChain(data []byte) {
	h.chainKey = addToChainKey(h.chainKey, data)
}

func (h *Handshake) CreateMessageInital() (*MessageInital, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	// reset handshake

	var err error
	h.ephemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	h.chainKey = InitalChainKey
	h.hash = addToHash(InitalHash, h.device.publicKey[:])

	// create ephemeral key

	var msg MessageInital
	msg.Type = MessageInitalType
	msg.Sender = h.device.NewID(h)
	msg.Ephemeral = h.ephemeral.publicKey()
	h.chainKey = addToChainKey(h.chainKey, msg.Ephemeral[:])
	h.hash = addToHash(h.hash, msg.Ephemeral[:])

	// encrypt long-term "identity key"

	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := h.ephemeral.sharedSecret(h.peer.publicKey)
		h.chainKey, key = KDF2(h.chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Static[:0], ZeroNonce[:], h.device.publicKey[:], nil)
	}()
	h.addHash(msg.Static[:])

	// encrypt timestamp

	timestamp := Timestamp()
	func() {
		var key [chacha20poly1305.KeySize]byte
		h.chainKey, key = KDF2(h.chainKey[:], h.staticStatic[:])
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], nil)
	}()
	h.addHash(msg.Timestamp[:])
	h.state = HandshakeInitialCreated
	return &msg, nil
}

func (h *Handshake) ConsumeMessageInitial(msg *MessageInital) error {
	if msg.Type != MessageInitalType {
		panic(errors.New("bug: invalid inital message type"))
	}

	hash := addToHash(InitalHash, h.device.publicKey[:])
	chainKey := addToChainKey(InitalChainKey, msg.Ephemeral[:])
	hash = addToHash(hash, msg.Ephemeral[:])

	//

	ephemeral, err := newPrivateKey()
	if err != nil {
		return err
	}

	// update handshake state

	h.lock.Lock()
	defer h.lock.Unlock()

	h.hash = hash
	h.chainKey = chainKey
	h.remoteIndex = msg.Sender
	h.ephemeral = ephemeral
	h.state = HandshakeInitialConsumed

	return nil

}

func (h *Handshake) CreateMessageResponse() []byte {

	return nil
}
