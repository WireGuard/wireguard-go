package main

import (
	"crypto/cipher"
	"sync"
	"time"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely ereased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

type KeyPair struct {
	send         cipher.AEAD
	receive      cipher.AEAD
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
	device.indices.Delete(key.localIndex)
}
