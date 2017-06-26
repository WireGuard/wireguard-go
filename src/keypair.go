package main

import (
	"crypto/cipher"
	"sync"
)

type KeyPair struct {
	recv      cipher.AEAD
	recvNonce uint64
	send      cipher.AEAD
	sendNonce uint64
}

type KeyPairs struct {
	mutex      sync.RWMutex
	current    *KeyPair
	previous   *KeyPair
	next       *KeyPair
	newKeyPair chan bool
}
