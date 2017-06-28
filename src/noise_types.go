package main

import (
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NoisePublicKeySize  = 32
	NoisePrivateKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoiseSymmetricKey [chacha20poly1305.KeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("Hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	for _, b := range key[:] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (key *NoisePrivateKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePrivateKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

func (key *NoiseSymmetricKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoiseSymmetricKey) ToHex() string {
	return hex.EncodeToString(key[:])
}
