package wgcfg

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const KeySize = 32

// PublicKey is curve25519 key.
// It is used by WireGuard to represent public and preshared keys.
type PublicKey [KeySize]byte

func ParseKey(b64 string) (*PublicKey, error) { return parseKeyBase64(base64.StdEncoding, b64) }

func ParseHexKey(s string) (PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return PublicKey{}, &ParseError{"invalid hex key: " + err.Error(), s}
	}
	if len(b) != KeySize {
		return PublicKey{}, &ParseError{fmt.Sprintf("invalid hex key length: %d", len(b)), s}
	}

	var key PublicKey
	copy(key[:], b)
	return key, nil
}

func ParsePrivateHexKey(v string) (PrivateKey, error) {
	k, err := ParseHexKey(v)
	if err != nil {
		return PrivateKey{}, err
	}
	pk := PrivateKey(k)
	if pk.IsZero() {
		// Do not clamp a zero key, pass the zero through
		// (much like NaN propagation) so that IsZero reports
		// a useful result.
		return pk, nil
	}
	pk.clamp()
	return pk, nil
}

func (k PublicKey) Base64() string          { return base64.StdEncoding.EncodeToString(k[:]) }
func (k PublicKey) String() string          { return k.ShortString() }
func (k PublicKey) HexString() string       { return hex.EncodeToString(k[:]) }
func (k PublicKey) Equal(k2 PublicKey) bool { return subtle.ConstantTimeCompare(k[:], k2[:]) == 1 }

func (k *PublicKey) ShortString() string {
	long := k.Base64()
	return "[" + long[0:5] + "]"
}

func (k PublicKey) IsZero() bool {
	var zeros PublicKey
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

// PrivateKey is curve25519 key.
// It is used by WireGuard to represent private keys.
type PrivateKey [KeySize]byte

// NewPrivateKey generates a new curve25519 secret key.
// It conforms to the format described on https://cr.yp.to/ecdh.html.
func NewPrivateKey() (pk PrivateKey, err error) {
	_, err = cryptorand.Read(pk[:])
	if err != nil {
		return PrivateKey{}, err
	}
	pk.clamp()
	return pk, nil
}

func ParsePrivateKey(b64 string) (*PrivateKey, error) {
	k, err := parseKeyBase64(base64.StdEncoding, b64)
	return (*PrivateKey)(k), err
}

func (k *PrivateKey) String() string           { return base64.StdEncoding.EncodeToString(k[:]) }
func (k *PrivateKey) HexString() string        { return hex.EncodeToString(k[:]) }
func (k *PrivateKey) Equal(k2 PrivateKey) bool { return subtle.ConstantTimeCompare(k[:], k2[:]) == 1 }

func (k PrivateKey) IsZero() bool {
	var zeros PrivateKey
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func (k *PrivateKey) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// Public computes the public key matching this curve25519 secret key.
func (k PrivateKey) Public() PublicKey {
	if k.IsZero() {
		panic("wgcfg: tried to generate public key for a zero key")
	}
	var p [KeySize]byte
	curve25519.ScalarBaseMult(&p, (*[KeySize]byte)(&k))
	return (PublicKey)(p)
}

func (k PrivateKey) MarshalText() ([]byte, error) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `privkey:%x`, k[:])
	return buf.Bytes(), nil
}

func (k *PrivateKey) UnmarshalText(b []byte) error {
	s := string(b)
	if !strings.HasPrefix(s, `privkey:`) {
		return errors.New("wgcfg.PrivateKey: UnmarshalText not given a private-key string")
	}
	s = strings.TrimPrefix(s, `privkey:`)
	key, err := ParseHexKey(s)
	if err != nil {
		return fmt.Errorf("wgcfg.PrivateKey: UnmarshalText: %v", err)
	}
	copy(k[:], key[:])
	return nil
}

func (k PrivateKey) SharedSecret(pub PublicKey) (ss [KeySize]byte) {
	apk := (*[KeySize]byte)(&pub)
	ask := (*[KeySize]byte)(&k)
	curve25519.ScalarMult(&ss, ask, apk)
	return ss
}

func parseKeyBase64(enc *base64.Encoding, s string) (*PublicKey, error) {
	k, err := enc.DecodeString(s)
	if err != nil {
		return nil, &ParseError{"Invalid key: " + err.Error(), s}
	}
	if len(k) != KeySize {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key PublicKey
	copy(key[:], k)
	return &key, nil
}

func ParseSymmetricKey(b64 string) (SymmetricKey, error) {
	k, err := parseKeyBase64(base64.StdEncoding, b64)
	if err != nil {
		return SymmetricKey{}, err
	}
	return SymmetricKey(*k), nil
}

func ParseSymmetricHexKey(s string) (SymmetricKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return SymmetricKey{}, &ParseError{"invalid symmetric hex key: " + err.Error(), s}
	}
	if len(b) != chacha20poly1305.KeySize {
		return SymmetricKey{}, &ParseError{fmt.Sprintf("invalid symmetric hex key length: %d", len(b)), s}
	}
	var key SymmetricKey
	copy(key[:], b)
	return key, nil
}

// SymmetricKey is a 32-byte value used as a pre-shared key.
type SymmetricKey [chacha20poly1305.KeySize]byte

func (k SymmetricKey) Base64() string             { return base64.StdEncoding.EncodeToString(k[:]) }
func (k SymmetricKey) String() string             { return "sym:" + k.Base64()[:8] }
func (k SymmetricKey) HexString() string          { return hex.EncodeToString(k[:]) }
func (k SymmetricKey) IsZero() bool               { return k.Equal(SymmetricKey{}) }
func (k SymmetricKey) Equal(k2 SymmetricKey) bool { return subtle.ConstantTimeCompare(k[:], k2[:]) == 1 }
