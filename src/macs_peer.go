package main

import (
	"crypto/cipher"
	"errors"
	"github.com/aead/chacha20poly1305" // Needed for XChaCha20Poly1305, TODO:
	"golang.org/x/crypto/blake2s"
	"sync"
	"time"
)

type MACStatePeer struct {
	mutex     sync.RWMutex
	cookieSet time.Time
	cookie    [blake2s.Size128]byte
	lastMAC1  [blake2s.Size128]byte
	keyMAC1   [blake2s.Size]byte
	keyMAC2   [blake2s.Size]byte
	xaead     cipher.AEAD
}

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

	state.xaead, _ = chacha20poly1305.NewXCipher(state.keyMAC2[:])
	state.cookieSet = time.Time{} // never
}

func (state *MACStatePeer) AddMacs(msg []byte) {
	size := len(msg)

	if size < blake2s.Size128*2 {
		panic(errors.New("bug: message too short"))
	}

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
		mac.Sum(state.lastMAC1[:0])
	}()
	copy(mac1, state.lastMAC1[:])

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
