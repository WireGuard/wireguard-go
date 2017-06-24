package main

import (
	"crypto/cipher"
)

type KeyPair struct {
	recieveKey   cipher.AEAD
	recieveNonce NoiseNonce
	sendKey      cipher.AEAD
	sendNonce    NoiseNonce
}
