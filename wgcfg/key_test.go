package wgcfg

import (
	"bytes"
	"testing"
)

func TestKeyBasics(t *testing.T) {
	pk1, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	k1 := pk1.Public()

	t.Run("second key", func(t *testing.T) {
		// Different keys should be different.
		pk2, err := NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		k2 := pk2.Public()
		if bytes.Equal(k1[:], k2[:]) {
			t.Fatalf("k1 %v == k2 %v", k1[:], k2[:])
		}
		// Check for obvious comparables to make sure we are not generating bad strings somewhere.
		if b1, b2 := k1.String(), k2.String(); b1 == b2 {
			t.Fatalf("base64-encoded keys match: %s, %s", b1, b2)
		}
		if pub1, pub2 := pk1.Public().String(), pk2.Public().String(); pub1 == pub2 {
			t.Fatalf("base64-encoded public keys match: %s, %s", pub1, pub2)
		}
	})
}
