package main

import (
	"sync"
)

type Device struct {
	mutex      sync.RWMutex
	peers      map[NoisePublicKey]*Peer
	privateKey NoisePrivateKey
	publicKey  NoisePublicKey
	fwMark     uint32
	listenPort uint16
}
