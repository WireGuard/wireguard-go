/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Andreas Auernhammer. All Rights Reserved.
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package xchacha20poly1305

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
)

func hChaCha20(out *[32]byte, nonce []byte, key *[32]byte) {

	v00 := uint32(0x61707865)
	v01 := uint32(0x3320646e)
	v02 := uint32(0x79622d32)
	v03 := uint32(0x6b206574)

	v04 := binary.LittleEndian.Uint32(key[0:])
	v05 := binary.LittleEndian.Uint32(key[4:])
	v06 := binary.LittleEndian.Uint32(key[8:])
	v07 := binary.LittleEndian.Uint32(key[12:])
	v08 := binary.LittleEndian.Uint32(key[16:])
	v09 := binary.LittleEndian.Uint32(key[20:])
	v10 := binary.LittleEndian.Uint32(key[24:])
	v11 := binary.LittleEndian.Uint32(key[28:])
	v12 := binary.LittleEndian.Uint32(nonce[0:])
	v13 := binary.LittleEndian.Uint32(nonce[4:])
	v14 := binary.LittleEndian.Uint32(nonce[8:])
	v15 := binary.LittleEndian.Uint32(nonce[12:])

	for i := 0; i < 20; i += 2 {
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 16) | (v12 >> 16)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 12) | (v04 >> 20)
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 8) | (v12 >> 24)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 7) | (v04 >> 25)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 16) | (v13 >> 16)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 12) | (v05 >> 20)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 8) | (v13 >> 24)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 7) | (v05 >> 25)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 16) | (v14 >> 16)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 12) | (v06 >> 20)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 8) | (v14 >> 24)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 7) | (v06 >> 25)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 16) | (v15 >> 16)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 12) | (v07 >> 20)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 8) | (v15 >> 24)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 7) | (v07 >> 25)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 16) | (v15 >> 16)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 12) | (v05 >> 20)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 8) | (v15 >> 24)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 7) | (v05 >> 25)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 16) | (v12 >> 16)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 12) | (v06 >> 20)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 8) | (v12 >> 24)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 7) | (v06 >> 25)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 16) | (v13 >> 16)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 12) | (v07 >> 20)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 8) | (v13 >> 24)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 7) | (v07 >> 25)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 16) | (v14 >> 16)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 12) | (v04 >> 20)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 8) | (v14 >> 24)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 7) | (v04 >> 25)
	}

	binary.LittleEndian.PutUint32(out[0:], v00)
	binary.LittleEndian.PutUint32(out[4:], v01)
	binary.LittleEndian.PutUint32(out[8:], v02)
	binary.LittleEndian.PutUint32(out[12:], v03)
	binary.LittleEndian.PutUint32(out[16:], v12)
	binary.LittleEndian.PutUint32(out[20:], v13)
	binary.LittleEndian.PutUint32(out[24:], v14)
	binary.LittleEndian.PutUint32(out[28:], v15)
}

func Encrypt(
	dst []byte,
	nonceFull *[24]byte,
	plaintext []byte,
	additionalData []byte,
	key *[chacha20poly1305.KeySize]byte,
) []byte {
	var nonce [chacha20poly1305.NonceSize]byte
	var derivedKey [chacha20poly1305.KeySize]byte
	hChaCha20(&derivedKey, nonceFull[:16], key)
	aead, _ := chacha20poly1305.New(derivedKey[:])
	copy(nonce[4:], nonceFull[16:])
	return aead.Seal(dst, nonce[:], plaintext, additionalData)
}

func Decrypt(
	dst []byte,
	nonceFull *[24]byte,
	plaintext []byte,
	additionalData []byte,
	key *[chacha20poly1305.KeySize]byte,
) ([]byte, error) {
	var nonce [chacha20poly1305.NonceSize]byte
	var derivedKey [chacha20poly1305.KeySize]byte
	hChaCha20(&derivedKey, nonceFull[:16], key)
	aead, _ := chacha20poly1305.New(derivedKey[:])
	copy(nonce[4:], nonceFull[16:])
	return aead.Open(dst, nonce[:], plaintext, additionalData)
}
