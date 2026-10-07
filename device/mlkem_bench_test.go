package device

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tai64n"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func BenchmarkKyberEncapsulate(b *testing.B) {
	scheme := kyber1024.Scheme()
	pk, _, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := scheme.Encapsulate(pk)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKyberDecapsulate(b *testing.B) {
	scheme := kyber1024.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	ct, _, err := scheme.Encapsulate(pk)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := scheme.Decapsulate(sk, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshakeWithMLKEM(b *testing.B) {
	skA, _ := newPrivateKey()
	skB, _ := newPrivateKey()
	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()
	devA := NewDevice(tunA.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	devB := NewDevice(tunB.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer devA.Close()
	defer devB.Close()

	if err := devA.SetPrivateKey(skA); err != nil {
		b.Fatal(err)
	}
	if err := devB.SetPrivateKey(skB); err != nil {
		b.Fatal(err)
	}

	peerB, err := devA.NewPeer(skB.publicKey())
	if err != nil {
		b.Fatal(err)
	}
	peerA, err := devB.NewPeer(skA.publicKey())
	if err != nil {
		b.Fatal(err)
	}

	scheme := kyber1024.Scheme()
	pkA, skAkem, _ := scheme.GenerateKeyPair()
	pkB, skBkem, _ := scheme.GenerateKeyPair()
	pkAb, _ := pkA.MarshalBinary()
	pkBb, _ := pkB.MarshalBinary()
	skAb, _ := skAkem.MarshalBinary()
	skBb, _ := skBkem.MarshalBinary()

	if err := devA.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skAb))); err != nil {
		b.Fatal(err)
	}
	if err := devB.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skBb))); err != nil {
		b.Fatal(err)
	}
	if err := devA.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerB.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkBb))); err != nil {
		b.Fatal(err)
	}
	if err := devB.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerA.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkAb))); err != nil {
		b.Fatal(err)
	}

	mldsaPubA, mldsaPrivA, err := GenerateMLDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	mldsaPubB, mldsaPrivB, err := GenerateMLDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	devA.staticIdentity.Lock()
	copy(devA.staticIdentity.mldsaPrivateKey[:], mldsaPrivA)
	copy(devA.staticIdentity.mldsaPublicKey[:], mldsaPubA)
	devA.staticIdentity.Unlock()

	devB.staticIdentity.Lock()
	copy(devB.staticIdentity.mldsaPrivateKey[:], mldsaPrivB)
	copy(devB.staticIdentity.mldsaPublicKey[:], mldsaPubB)
	devB.staticIdentity.Unlock()

	peerB.handshake.mutex.Lock()
	copy(peerB.handshake.remoteMLDSAStatic[:], mldsaPubB)
	peerB.handshake.mutex.Unlock()

	peerA.handshake.mutex.Lock()
	copy(peerA.handshake.remoteMLDSAStatic[:], mldsaPubA)
	peerA.handshake.mutex.Unlock()

	relaxFlood := func() {
		peerA.handshake.mutex.Lock()
		peerA.handshake.lastInitiationConsumption = time.Now().Add(-10 * time.Second)
		peerA.handshake.lastTimestamp = tai64n.Timestamp{}
		peerA.handshake.mutex.Unlock()
	}
	relaxFlood()
	msg1, err := devA.CreateMessageInitiation(peerB)
	if err != nil {
		b.Fatal(err)
	}
	if p := devB.ConsumeMessageInitiation(msg1); p == nil {
		b.Fatal("initiation fail (warmup)")
	}
	msg2, err := devB.CreateMessageResponse(peerA)
	if err != nil {
		b.Fatal(err)
	}
	if p := devA.ConsumeMessageResponse(msg2); p == nil {
		b.Fatal("response fail (warmup)")
	}
	if err := peerA.BeginSymmetricSession(); err != nil {
		b.Fatal(err)
	}
	if err := peerB.BeginSymmetricSession(); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		relaxFlood()
		msg1, err := devA.CreateMessageInitiation(peerB)
		if err != nil {
			b.Fatal(err)
		}
		if p := devB.ConsumeMessageInitiation(msg1); p == nil {
			b.Fatal("initiation fail")
		}
		msg2, err := devB.CreateMessageResponse(peerA)
		if err != nil {
			b.Fatal(err)
		}
		if p := devA.ConsumeMessageResponse(msg2); p == nil {
			b.Fatal("response fail")
		}
		if err := peerA.BeginSymmetricSession(); err != nil {
			b.Fatal(err)
		}
		if err := peerB.BeginSymmetricSession(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshakeHybrid(b *testing.B) {
	skA, _ := newPrivateKey()
	skB, _ := newPrivateKey()
	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()
	devA := NewDevice(tunA.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	devB := NewDevice(tunB.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer devA.Close()
	defer devB.Close()

	if err := devA.IpcSet(uapiCfg("private_key", hex.EncodeToString(skA[:]))); err != nil {
		b.Fatal(err)
	}
	if err := devB.IpcSet(uapiCfg("private_key", hex.EncodeToString(skB[:]))); err != nil {
		b.Fatal(err)
	}

	scheme := kyber1024.Scheme()
	pkA, skAkem, _ := scheme.GenerateKeyPair()
	pkB, skBkem, _ := scheme.GenerateKeyPair()
	pkAb, _ := pkA.MarshalBinary()
	pkBb, _ := pkB.MarshalBinary()
	skAb, _ := skAkem.MarshalBinary()
	skBb, _ := skBkem.MarshalBinary()

	if err := devA.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skAb))); err != nil {
		b.Fatal(err)
	}
	if err := devB.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skBb))); err != nil {
		b.Fatal(err)
	}

	pkBNoise := skB.publicKey()
	pkANoise := skA.publicKey()
	if err := devA.IpcSet(uapiCfg("public_key", hex.EncodeToString(pkBNoise[:]), "mlkem_public_key", hex.EncodeToString(pkBb))); err != nil {
		b.Fatal(err)
	}
	if err := devB.IpcSet(uapiCfg("public_key", hex.EncodeToString(pkANoise[:]), "mlkem_public_key", hex.EncodeToString(pkAb))); err != nil {
		b.Fatal(err)
	}

	peerB := devA.LookupPeer(pkBNoise)
	peerA := devB.LookupPeer(pkANoise)
	if peerA == nil || peerB == nil {
		b.Fatal("peer lookup failed (check IpcSet order)")
	}

	mldsaPubA, mldsaPrivA, err := GenerateMLDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	mldsaPubB, mldsaPrivB, err := GenerateMLDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	devA.staticIdentity.Lock()
	copy(devA.staticIdentity.mldsaPrivateKey[:], mldsaPrivA)
	copy(devA.staticIdentity.mldsaPublicKey[:], mldsaPubA)
	devA.staticIdentity.Unlock()

	devB.staticIdentity.Lock()
	copy(devB.staticIdentity.mldsaPrivateKey[:], mldsaPrivB)
	copy(devB.staticIdentity.mldsaPublicKey[:], mldsaPubB)
	devB.staticIdentity.Unlock()

	peerB.handshake.mutex.Lock()
	copy(peerB.handshake.remoteMLDSAStatic[:], mldsaPubB)
	peerB.handshake.mutex.Unlock()

	peerA.handshake.mutex.Lock()
	copy(peerA.handshake.remoteMLDSAStatic[:], mldsaPubA)
	peerA.handshake.mutex.Unlock()

	relax := func() {
		peerA.handshake.mutex.Lock()
		peerA.handshake.lastInitiationConsumption = time.Now().Add(-10 * time.Second)
		peerA.handshake.lastTimestamp = tai64n.Timestamp{}
		peerA.handshake.mutex.Unlock()
	}
	relax()
	msg1, _ := devA.CreateMessageInitiation(peerB)
	devB.ConsumeMessageInitiation(msg1)
	msg2, _ := devB.CreateMessageResponse(peerA)
	devA.ConsumeMessageResponse(msg2)
	peerA.BeginSymmetricSession()
	peerB.BeginSymmetricSession()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		relax()
		msg1, _ := devA.CreateMessageInitiation(peerB)
		devB.ConsumeMessageInitiation(msg1)
		msg2, _ := devB.CreateMessageResponse(peerA)
		devA.ConsumeMessageResponse(msg2)
		peerA.BeginSymmetricSession()
		peerB.BeginSymmetricSession()
	}
}

func BenchmarkDataPlaneAEAD(b *testing.B) {
	skA, _ := newPrivateKey()
	skB, _ := newPrivateKey()
	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()
	devA := NewDevice(tunA.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	devB := NewDevice(tunB.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer devA.Close()
	defer devB.Close()
	devA.SetPrivateKey(skA)
	devB.SetPrivateKey(skB)
	peerB, _ := devA.NewPeer(skB.publicKey())
	peerA, _ := devB.NewPeer(skA.publicKey())

	scheme := kyber1024.Scheme()
	pkA, skAkem, _ := scheme.GenerateKeyPair()
	pkB, skBkem, _ := scheme.GenerateKeyPair()
	pkAb, _ := pkA.MarshalBinary()
	pkBb, _ := pkB.MarshalBinary()
	skAb, _ := skAkem.MarshalBinary()
	skBb, _ := skBkem.MarshalBinary()
	devA.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skAb)))
	devB.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skBb)))
	devA.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerB.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkBb)))
	devB.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerA.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkAb)))
	mldsaPubA, mldsaPrivA, err := GenerateMLDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	mldsaPubB, mldsaPrivB, err := GenerateMLDSAKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	devA.staticIdentity.Lock()
	copy(devA.staticIdentity.mldsaPrivateKey[:], mldsaPrivA)
	copy(devA.staticIdentity.mldsaPublicKey[:], mldsaPubA)
	devA.staticIdentity.Unlock()

	devB.staticIdentity.Lock()
	copy(devB.staticIdentity.mldsaPrivateKey[:], mldsaPrivB)
	copy(devB.staticIdentity.mldsaPublicKey[:], mldsaPubB)
	devB.staticIdentity.Unlock()

	peerB.handshake.mutex.Lock()
	copy(peerB.handshake.remoteMLDSAStatic[:], mldsaPubB)
	peerB.handshake.mutex.Unlock()

	peerA.handshake.mutex.Lock()
	copy(peerA.handshake.remoteMLDSAStatic[:], mldsaPubA)
	peerA.handshake.mutex.Unlock()
	msg1, _ := devA.CreateMessageInitiation(peerB)
	devB.ConsumeMessageInitiation(msg1)
	msg2, _ := devB.CreateMessageResponse(peerA)
	devA.ConsumeMessageResponse(msg2)
	peerA.BeginSymmetricSession()
	peerB.BeginSymmetricSession()

	keyA := peerA.keypairs.next.Load()
	keyB := peerB.keypairs.current
	msg := bytes.Repeat([]byte{0x42}, 128)
	var nonce [12]byte

	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := keyA.send.Seal(nil, nonce[:], msg, nil)
		_, err := keyB.receive.Open(nil, nonce[:], out, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataPlaneAEADHybrid(b *testing.B) {
    skA, _ := newPrivateKey()
    skB, _ := newPrivateKey()
    tunA := tuntest.NewChannelTUN()
    tunB := tuntest.NewChannelTUN()
    devA := NewDevice(tunA.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
    devB := NewDevice(tunB.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
    defer devA.Close()
    defer devB.Close()

    if err := devA.IpcSet(uapiCfg("private_key", hex.EncodeToString(skA[:]))); err != nil {
        b.Fatal(err)
    }
    if err := devB.IpcSet(uapiCfg("private_key", hex.EncodeToString(skB[:]))); err != nil {
        b.Fatal(err)
    }

    scheme := kyber1024.Scheme()
    pkA, skAkem, _ := scheme.GenerateKeyPair()
    pkB, skBkem, _ := scheme.GenerateKeyPair()
    pkAb, _ := pkA.MarshalBinary()
    pkBb, _ := pkB.MarshalBinary()
    skAb, _ := skAkem.MarshalBinary()
    skBb, _ := skBkem.MarshalBinary()

    if err := devA.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skAb))); err != nil {
        b.Fatal(err)
    }
    if err := devB.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skBb))); err != nil {
        b.Fatal(err)
    }

    pkBNoise := skB.publicKey()
    pkANoise := skA.publicKey()
    if err := devA.IpcSet(uapiCfg("public_key", hex.EncodeToString(pkBNoise[:]), "mlkem_public_key", hex.EncodeToString(pkBb))); err != nil {
        b.Fatal(err)
    }
    if err := devB.IpcSet(uapiCfg("public_key", hex.EncodeToString(pkANoise[:]), "mlkem_public_key", hex.EncodeToString(pkAb))); err != nil {
        b.Fatal(err)
    }

    peerB := devA.LookupPeer(pkBNoise)
    peerA := devB.LookupPeer(pkANoise)
    if peerA == nil || peerB == nil {
        b.Fatal("peer lookup failed (check IpcSet order)")
    }

    mldsaPubA, mldsaPrivA, err := GenerateMLDSAKeyPair()
    if err != nil {
        b.Fatal(err)
    }
    mldsaPubB, mldsaPrivB, err := GenerateMLDSAKeyPair()
    if err != nil {
        b.Fatal(err)
    }

    devA.staticIdentity.Lock()
    copy(devA.staticIdentity.mldsaPrivateKey[:], mldsaPrivA)
    copy(devA.staticIdentity.mldsaPublicKey[:], mldsaPubA)
    devA.staticIdentity.Unlock()

    devB.staticIdentity.Lock()
    copy(devB.staticIdentity.mldsaPrivateKey[:], mldsaPrivB)
    copy(devB.staticIdentity.mldsaPublicKey[:], mldsaPubB)
    devB.staticIdentity.Unlock()

    peerB.handshake.mutex.Lock()
    copy(peerB.handshake.remoteMLDSAStatic[:], mldsaPubB)
    peerB.handshake.mutex.Unlock()

    peerA.handshake.mutex.Lock()
    copy(peerA.handshake.remoteMLDSAStatic[:], mldsaPubA)
    peerA.handshake.mutex.Unlock()

    msg1, _ := devA.CreateMessageInitiation(peerB)
    devB.ConsumeMessageInitiation(msg1)
    msg2, _ := devB.CreateMessageResponse(peerA)
    devA.ConsumeMessageResponse(msg2)
    peerA.BeginSymmetricSession()
    peerB.BeginSymmetricSession()

    keyA := peerA.keypairs.next.Load()
    keyB := peerB.keypairs.current
    msg := bytes.Repeat([]byte{0x42}, 128)
    var nonce [12]byte

    b.ReportAllocs()
    b.SetBytes(int64(len(msg)))
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        out := keyA.send.Seal(nil, nonce[:], msg, nil)
        _, err := keyB.receive.Open(nil, nonce[:], out, nil)
        if err != nil {
            b.Fatal(err)
        }
    }
}

