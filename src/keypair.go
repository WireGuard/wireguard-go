package main

import (
	"crypto/cipher"
	"golang.org/x/crypto/chacha20poly1305"
	"reflect"
	"sync"
	"time"
)

type safeAEAD struct {
	mutex sync.RWMutex
	aead  cipher.AEAD
}

func (con *safeAEAD) clear() {
	// TODO: improve handling of key material
	con.mutex.Lock()
	if con.aead != nil {
		val := reflect.ValueOf(con.aead)
		elm := val.Elem()
		typ := elm.Type()
		elm.Set(reflect.Zero(typ))
		con.aead = nil
	}
	con.mutex.Unlock()
}

func (con *safeAEAD) setKey(key *[chacha20poly1305.KeySize]byte) {
	// TODO: improve handling of key material
	con.aead, _ = chacha20poly1305.New(key[:])
}

type KeyPair struct {
	send         safeAEAD
	receive      safeAEAD
	replayFilter ReplayFilter
	sendNonce    uint64
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
}

type KeyPairs struct {
	mutex    sync.RWMutex
	current  *KeyPair
	previous *KeyPair
	next     *KeyPair // not yet "confirmed by transport"
}

func (kp *KeyPairs) Current() *KeyPair {
	kp.mutex.RLock()
	defer kp.mutex.RUnlock()
	return kp.current
}

func (device *Device) DeleteKeyPair(key *KeyPair) {
	key.send.clear()
	key.receive.clear()
	device.indices.Delete(key.localIndex)
}
