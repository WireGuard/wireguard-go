package main

import (
	"crypto/cipher"
)

type KeyPair struct {
	recv      cipher.AEAD
	recvNonce NoiseNonce
	send      cipher.AEAD
	sendNonce NoiseNonce
}
