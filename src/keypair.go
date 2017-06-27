package main

import (
	"crypto/cipher"
	"sync"
	"time"
)

type KeyPair struct {
	recv        cipher.AEAD
	recvNonce   uint64
	send        cipher.AEAD
	sendNonce   uint64
	isInitiator bool
	created     time.Time
}

type KeyPairs struct {
	mutex      sync.RWMutex
	current    *KeyPair
	previous   *KeyPair
	next       *KeyPair  // not yet "confirmed by transport"
	newKeyPair chan bool // signals when "current" has been updated
}

func (kp *KeyPairs) Init() {
	kp.mutex.Lock()
	kp.newKeyPair = make(chan bool, 5)
	kp.mutex.Unlock()
}

func (kp *KeyPairs) Current() *KeyPair {
	kp.mutex.RLock()
	defer kp.mutex.RUnlock()
	return kp.current
}
