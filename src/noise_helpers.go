package main

import (
	"crypto/hmac"
	"crypto/rand"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
	"hash"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC(sum *[blake2s.Size]byte, key []byte, input []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(input)
	mac.Sum(sum[:0])
}

func KDF1(key []byte, input []byte) (t0 [blake2s.Size]byte) {
	HMAC(&t0, key, input)
	HMAC(&t0, t0[:], []byte{0x1})
	return
}

func KDF2(key []byte, input []byte) (t0 [blake2s.Size]byte, t1 [blake2s.Size]byte) {
	var prk [blake2s.Size]byte
	HMAC(&prk, key, input)
	HMAC(&t0, prk[:], []byte{0x1})
	HMAC(&t1, prk[:], append(t0[:], 0x2))
	prk = [blake2s.Size]byte{}
	return
}

func KDF3(key []byte, input []byte) (t0 [blake2s.Size]byte, t1 [blake2s.Size]byte, t2 [blake2s.Size]byte) {
	var prk [blake2s.Size]byte
	HMAC(&prk, key, input)
	HMAC(&t0, prk[:], []byte{0x1})
	HMAC(&t1, prk[:], append(t0[:], 0x2))
	HMAC(&t2, prk[:], append(t1[:], 0x3))
	prk = [blake2s.Size]byte{}
	return
}

/* curve25519 wrappers */

func newPrivateKey() (sk NoisePrivateKey, err error) {
	// clamping: https://cr.yp.to/ecdh.html
	_, err = rand.Read(sk[:])
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	return ss
}
