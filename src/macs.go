package main

import (
	"crypto/hmac"
	"crypto/rand"
	"golang.org/x/crypto/blake2s"
	"net"
	"sync"
	"time"
)

type MACStateDevice struct {
	mutex     sync.RWMutex
	refreshed time.Time
	secret    [blake2s.Size]byte
	keyMAC1   [blake2s.Size]byte
	keyMAC2   [blake2s.Size]byte // TODO: Change to more descriptive size constant, rename to something.
}

type MACStatePeer struct {
	mutex     sync.RWMutex
	cookieSet time.Time
	cookie    [blake2s.Size128]byte
	lastMAC1  [blake2s.Size128]byte // TODO: Check if set
	keyMAC1   [blake2s.Size]byte
	keyMAC2   [blake2s.Size]byte
}

/* Methods for verifing MAC fields
 * and creating/consuming cookies replies
 * (per device)
 */

func (state *MACStateDevice) Init(pk NoisePublicKey) {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	func() {
		hsh, _ := blake2s.New256(nil)
		hsh.Write([]byte(WGLabelMAC1))
		hsh.Write(pk[:])
		hsh.Sum(state.keyMAC1[:0])
	}()

	func() {
		hsh, _ := blake2s.New256(nil)
		hsh.Write([]byte(WGLabelCookie))
		hsh.Write(pk[:])
		hsh.Sum(state.keyMAC2[:0])
	}()

	state.refreshed = time.Time{}
}

func (state *MACStateDevice) CheckMAC1(msg []byte) bool {
	size := len(msg)
	startMac1 := size - (blake2s.Size128 * 2)
	startMac2 := size - blake2s.Size128

	var mac1 [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(state.keyMAC1[:])
		mac.Write(msg[:startMac1])
		mac.Sum(mac1[:0])
	}()

	return hmac.Equal(mac1[:], msg[startMac1:startMac2])
}

func (state *MACStateDevice) CheckMAC2(msg []byte, addr *net.UDPAddr) bool {
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
		mac.Write(port[:]) // TODO: Be faster and more platform dependent?
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

func (device *Device) CreateMessageCookieReply(
	msg []byte, receiver uint32, addr *net.UDPAddr,
) (*MessageCookieReply, error) {

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
		mac.Write(port[:]) // TODO: Do whatever we did above
		mac.Sum(cookie[:0])
	}()

	// encrypt cookie

	size := len(msg)

	startMac1 := size - (blake2s.Size128 * 2)
	startMac2 := size - blake2s.Size128

	mac1 := msg[startMac1:startMac2]

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = receiver
	_, err := rand.Read(reply.Nonce[:])
	if err != nil {
		state.mutex.RUnlock()
		return nil, err
	}

	XChaCha20Poly1305Encrypt(
		reply.Cookie[:0],
		&reply.Nonce,
		cookie[:],
		mac1,
		&state.keyMAC2,
	)

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

	_, err := XChaCha20Poly1305Decrypt(
		cookie[:0],
		&msg.Nonce,
		msg.Cookie[:],
		state.lastMAC1[:],
		&state.keyMAC2,
	)

	if err != nil {
		return false
	}

	state.cookieSet = time.Now()
	state.cookie = cookie
	return true
}

/* Methods for generating the MAC fields
 * (per peer)
 */

func (state *MACStatePeer) Init(pk NoisePublicKey) {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	func() {
		hsh, _ := blake2s.New256(nil)
		hsh.Write([]byte(WGLabelMAC1))
		hsh.Write(pk[:])
		hsh.Sum(state.keyMAC1[:0])
	}()

	func() {
		hsh, _ := blake2s.New256(nil)
		hsh.Write([]byte(WGLabelCookie))
		hsh.Write(pk[:])
		hsh.Sum(state.keyMAC2[:0])
	}()

	state.cookieSet = time.Time{} // never
}

func (state *MACStatePeer) AddMacs(msg []byte) {
	size := len(msg)

	startMac1 := size - (blake2s.Size128 * 2)
	startMac2 := size - blake2s.Size128

	mac1 := msg[startMac1 : startMac1+blake2s.Size128]
	mac2 := msg[startMac2 : startMac2+blake2s.Size128]

	state.mutex.Lock()
	defer state.mutex.Unlock()

	// set mac1

	func() {
		mac, _ := blake2s.New128(state.keyMAC1[:])
		mac.Write(msg[:startMac1])
		mac.Sum(mac1[:0])
	}()
	copy(state.lastMAC1[:], mac1)
	// TODO: Set lastMac flag

	// set mac2

	if state.cookieSet.IsZero() {
		return
	}
	if time.Now().Sub(state.cookieSet) > CookieRefreshTime {
		state.cookieSet = time.Time{}
		return
	}
	func() {
		mac, _ := blake2s.New128(state.cookie[:])
		mac.Write(msg[:startMac2])
		mac.Sum(mac2[:0])
	}()
}
