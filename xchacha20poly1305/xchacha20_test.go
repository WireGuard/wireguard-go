/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package xchacha20poly1305

import (
	"encoding/hex"
	"testing"
)

type XChaCha20Test struct {
	Nonce string
	Key   string
	PT    string
	CT    string
}

func TestXChaCha20(t *testing.T) {

	tests := []XChaCha20Test{
		{
			Nonce: "000000000000000000000000000000000000000000000000",
			Key:   "0000000000000000000000000000000000000000000000000000000000000000",
			PT:    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			CT:    "789e9689e5208d7fd9e1f3c5b5341f48ef18a13e418998addadd97a3693a987f8e82ecd5c1433bfed1af49750c0f1ff29c4174a05b119aa3a9e8333812e0c0feb1299c5949d895ee01dbf50f8395dd84",
		},
		{
			Nonce: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
			Key:   "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
			PT:    "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
			CT:    "e1a046aa7f71e2af8b80b6408b2fd8d3a350278cde79c94d9efaa475e1339b3dd490127b",
		},
		{
			Nonce: "d9a8213e8a697508805c2c171ad54487ead9e3e02d82d5bc",
			Key:   "979196dbd78526f2f584f7534db3f5824d8ccfa858ca7e09bdd3656ecd36033c",
			PT:    "43cc6d624e451bbed952c3e071dc6c03392ce11eb14316a94b2fdc98b22fedea",
			CT:    "53c1e8bef2dbb8f2505ec010a7afe21d5a8e6dd8f987e4ea1a2ed5dfbc844ea400db34496fd2153526c6e87c36694200",
		},
	}

	for _, test := range tests {

		nonce, err := hex.DecodeString(test.Nonce)
		if err != nil {
			panic(err)
		}

		key, err := hex.DecodeString(test.Key)
		if err != nil {
			panic(err)
		}

		pt, err := hex.DecodeString(test.PT)
		if err != nil {
			panic(err)
		}

		func() {
			var nonceArray [24]byte
			var keyArray [32]byte
			copy(nonceArray[:], nonce)
			copy(keyArray[:], key)

			// test encryption

			ct := Encrypt(
				nil,
				&nonceArray,
				pt,
				nil,
				&keyArray,
			)
			ctHex := hex.EncodeToString(ct)
			if ctHex != test.CT {
				t.Fatal("encryption failed, expected:", test.CT, "got", ctHex)
			}

			// test decryption

			ptp, err := Decrypt(
				nil,
				&nonceArray,
				ct,
				nil,
				&keyArray,
			)
			if err != nil {
				t.Fatal(err)
			}

			ptHex := hex.EncodeToString(ptp)
			if ptHex != test.PT {
				t.Fatal("decryption failed, expected:", test.PT, "got", ptHex)
			}
		}()

	}

}
