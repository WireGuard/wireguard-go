package main

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"github.com/aead/chacha20poly1305" // Needed for XChaCha20Poly1305, TODO:
	"golang.org/x/crypto/blake2s"
	"net"
	"sync"
	"time"
)

type MacStateDevice struct {
	mutex     sync.RWMutex
	refreshed time.Time
	secret    [blake2s.Size]byte
	keyMac1   [blake2s.Size]byte
	xaead     cipher.AEAD
}

func (state *MacStateDevice) Init(pk NoisePublicKey) {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	func() {
		hsh, _ := blake2s.New256(nil)
		hsh.Write([]byte(WGLabelMAC1))
		hsh.Write(pk[:])
		hsh.Sum(state.keyMac1[:0])
	}()
	state.xaead, _ = chacha20poly1305.NewXCipher(state.keyMac1[:])
	state.refreshed = time.Time{} // never
}

func (state *MacStateDevice) CheckMAC1(msg []byte) bool {
	size := len(msg)
	startMac1 := size - (blake2s.Size128 * 2)
	startMac2 := size - blake2s.Size128

	var mac1 [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(state.keyMac1[:])
		mac.Write(msg[:startMac1])
		mac.Sum(mac1[:0])
	}()

	return hmac.Equal(mac1[:], msg[startMac1:startMac2])
}

func (state *MacStateDevice) CheckMAC2(msg []byte, addr *net.UDPAddr) bool {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	if time.Now().Sub(state.refreshed) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	var cookie [blake2s.Size128]byte
	func() {
		port := [2]byte{byte(addr.Port >> 8), byte(addr.Port)}
		mac, _ := blake2s.New128(state.secret[:])
		mac.Write(addr.IP)
		mac.Write(port[:])
		mac.Sum(cookie[:0])
	}()

	// calculate mac of packet

	start := len(msg) - blake2s.Size128

	var mac2 [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(cookie[:])
		mac.Write(msg[:start])
		mac.Sum(mac2[:0])
	}()

	return hmac.Equal(mac2[:], msg[start:])
}

func (device *Device) CreateMessageCookieReply(msg []byte, receiver uint32, addr *net.UDPAddr) (*MessageCookieReply, error) {
	state := &device.mac
	state.mutex.RLock()

	// refresh cookie secret

	if time.Now().Sub(state.refreshed) > CookieRefreshTime {
		state.mutex.RUnlock()
		state.mutex.Lock()
		_, err := rand.Read(state.secret[:])
		if err != nil {
			state.mutex.Unlock()
			return nil, err
		}
		state.refreshed = time.Now()
		state.mutex.Unlock()
		state.mutex.RLock()
	}

	// derive cookie key

	var cookie [blake2s.Size128]byte
	func() {
		port := [2]byte{byte(addr.Port >> 8), byte(addr.Port)}
		mac, _ := blake2s.New128(state.secret[:])
		mac.Write(addr.IP)
		mac.Write(port[:])
		mac.Sum(cookie[:0])
	}()

	// encrypt cookie

	size := len(msg)

	startMac1 := size - (blake2s.Size128 * 2)
	startMac2 := size - blake2s.Size128

	M := msg[startMac1:startMac2]

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = receiver
	_, err := rand.Read(reply.Nonce[:])
	if err != nil {
		state.mutex.RUnlock()
		return nil, err
	}
	state.xaead.Seal(reply.Cookie[:0], reply.Nonce[:], cookie[:], M)
	state.mutex.RUnlock()
	return reply, nil
}

func (device *Device) ConsumeMessageCookieReply(msg *MessageCookieReply) bool {

	if msg.Type != MessageCookieReplyType {
		return false
	}

	// lookup peer

	lookup := device.indices.Lookup(msg.Receiver)
	if lookup.handshake == nil {
		return false
	}

	// decrypt and store cookie

	var cookie [blake2s.Size128]byte
	state := &lookup.peer.mac
	state.mutex.Lock()
	defer state.mutex.Unlock()
	_, err := state.xaead.Open(cookie[:0], msg.Nonce[:], msg.Cookie[:], state.lastMac1[:])
	if err != nil {
		return false
	}
	state.cookieSet = time.Now()
	state.cookie = cookie
	return true
}
