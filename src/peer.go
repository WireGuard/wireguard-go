package main

import (
	"sync"
)

type KeyPair struct {
	recieveKey   NoiseSymmetricKey
	recieveNonce NoiseNonce
	sendKey      NoiseSymmetricKey
	sendNonce    NoiseNonce
}

type Peer struct {
	mutex        sync.RWMutex
	publicKey    NoisePublicKey
	presharedKey NoiseSymmetricKey
}
