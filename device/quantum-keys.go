package device

import (
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

func GenerateQuantumKeyPair() (pub []byte, priv []byte, err error) {
	pk, sk, err := kyber1024.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}

func GenerateMLDSAKeyPair() (pub []byte, priv []byte, err error) {
	pk, sk, err := mode5.Scheme().GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}
