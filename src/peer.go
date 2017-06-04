package main

import (
	"net"
	"sync"
	"time"
)

type KeyPair struct {
	recieveKey   NoiseSymmetricKey
	recieveNonce NoiseNonce
	sendKey      NoiseSymmetricKey
	sendNonce    NoiseNonce
}

type Peer struct {
	mutex                       sync.RWMutex
	publicKey                   NoisePublicKey
	presharedKey                NoiseSymmetricKey
	endpoint                    net.IP
	persistentKeepaliveInterval time.Duration
}
