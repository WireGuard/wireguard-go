package main

import (
	"encoding/hex"
	"errors"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoiseSymmetricKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoiseSymmetricKey [NoiseSymmetricKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

func (key *NoisePrivateKey) FromHex(s string) error {
	slice, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(slice) != NoisePrivateKeySize {
		return errors.New("Invalid length of hex string for curve25519 point")
	}
	copy(key[:], slice)
	return nil
}

func (key *NoisePrivateKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

func (key *NoisePublicKey) FromHex(s string) error {
	slice, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(slice) != NoisePublicKeySize {
		return errors.New("Invalid length of hex string for curve25519 scalar")
	}
	copy(key[:], slice)
	return nil
}

func (key *NoisePublicKey) ToHex() string {
	return hex.EncodeToString(key[:])
}
