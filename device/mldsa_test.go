package device

import (
	"bytes"
	"testing"
	"encoding/hex"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

func TestGenerateMLDSAKeyPair(t *testing.T) {
	pub, priv, err := GenerateMLDSAKeyPair()
	if err != nil {
		t.Fatalf("erro gerando MLDSA: %v", err)
	}
	if len(pub) != MLDSAPublicKeySize || len(priv) != MLDSAPrivateKeySize {
		t.Fatalf("tamanhos inválidos: pub=%d priv=%d", len(pub), len(priv))
	}
	s := mode5.Scheme()
	if _, err := s.UnmarshalBinaryPublicKey(pub); err != nil {
		t.Fatalf("publicKey inválida: %v", err)
	}
	if _, err := s.UnmarshalBinaryPrivateKey(priv); err != nil {
		t.Fatalf("privateKey inválida: %v", err)
	}
}

func TestMLDSASignVerify(t *testing.T) {
	s := mode5.Scheme()
	pk, sk, err := s.GenerateKey()
	if err != nil {
		t.Fatalf("erro gerando par mldsa: %v", err)
	}
	msg := []byte("wireguard + mldsa test")
	sig := s.Sign(sk, msg, nil)

	if !s.Verify(pk, msg, sig, nil) {
		t.Fatalf("assinatura MLDSA não verificou")
	}
	if s.Verify(pk, append(msg, 0x01), sig, nil) {
		t.Fatalf("assinatura deveria falhar em msg alterada")
	}
}

func mustCopy(dst []byte, src []byte) {
	if len(dst) != len(src) { panic("tam inválido") }
	copy(dst, src)
}

func TestHybridHandshakeWithMLDSASignature(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	kyb := kyber1024.Scheme()
	pkK1, skK1, _ := kyb.GenerateKeyPair()
	pkK2, skK2, _ := kyb.GenerateKeyPair()
	pubK1, _ := pkK1.MarshalBinary()
	privK1, _ := skK1.MarshalBinary()
	pubK2, _ := pkK2.MarshalBinary()
	privK2, _ := skK2.MarshalBinary()

	mldsa := mode5.Scheme()
	pkS1, skS1, _ := mldsa.GenerateKey()
	pkS2, skS2, _ := mldsa.GenerateKey()
	pubS1, _ := pkS1.MarshalBinary()
	privS1, _ := skS1.MarshalBinary()
	pubS2, _ := pkS2.MarshalBinary()
	privS2, _ := skS2.MarshalBinary()

	mustCopy(dev1.staticIdentity.mlkemPrivateKey[:], privK1)
	mustCopy(dev2.staticIdentity.mlkemPrivateKey[:], privK2)
	mustCopy(dev1.staticIdentity.mldsaPrivateKey[:], privS1)
	mustCopy(dev2.staticIdentity.mldsaPrivateKey[:], privS2)

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil { t.Fatal(err) }
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil { t.Fatal(err) }

	mustCopy(peer1.handshake.remoteMLKEMStatic[:], pubK1)
	mustCopy(peer2.handshake.remoteMLKEMStatic[:], pubK2)
	mustCopy(peer1.handshake.remoteMLDSAStatic[:], pubS1)
	mustCopy(peer2.handshake.remoteMLDSAStatic[:], pubS2)

	peer1.Start()
	peer2.Start()

	init, err := dev1.CreateMessageInitiation(peer2)
	if err != nil {
		t.Fatalf("CreateMessageInitiation falhou: %v", err)
	}
	if p := dev2.ConsumeMessageInitiation(init); p == nil {
		t.Fatalf("ConsumeMessageInitiation falhou (assinatura/MLKEM?)")
	}

	resp, err := dev2.CreateMessageResponse(peer1)
	if err != nil {
		t.Fatalf("CreateMessageResponse falhou: %v", err)
	}
	if p := dev1.ConsumeMessageResponse(resp); p == nil {
		t.Fatalf("ConsumeMessageResponse falhou")
	}

	if err := peer1.BeginSymmetricSession(); err != nil {
		t.Fatalf("peer1.BeginSymmetricSession: %v", err)
	}
	if err := peer2.BeginSymmetricSession(); err != nil {
		t.Fatalf("peer2.BeginSymmetricSession: %v", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current
	plain := []byte("ok mldsa+mlkem+noise")
	var nonce [12]byte
	c := key1.send.Seal(nil, nonce[:], plain, nil)
	out, err := key2.receive.Open(nil, nonce[:], c, nil)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("falha cifrar/decifrar: %v", err)
	}
}

func TestHybridHandshake_MLDSAInvalidSignature(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close(); defer dev2.Close()

	kyb := kyber1024.Scheme()
	pkK1, skK1, _ := kyb.GenerateKeyPair()
	pkK2, skK2, _ := kyb.GenerateKeyPair()
	pubK1, _ := pkK1.MarshalBinary()
	privK1, _ := skK1.MarshalBinary()
	pubK2, _ := pkK2.MarshalBinary()
	privK2, _ := skK2.MarshalBinary()
	mustCopy(dev1.staticIdentity.mlkemPrivateKey[:], privK1)
	mustCopy(dev2.staticIdentity.mlkemPrivateKey[:], privK2)

	s := mode5.Scheme()
	pkGood, skGood, _ := s.GenerateKey()
	pkWrong, _, _ := s.GenerateKey()
	privGood, _ := skGood.MarshalBinary()
	pubGood, _ := pkGood.MarshalBinary()
	pubWrong, _ := pkWrong.MarshalBinary()
	mustCopy(dev1.staticIdentity.mldsaPrivateKey[:], privGood)

	peer1, _ := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	peer2, _ := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	peer1.Start(); peer2.Start()
	mustCopy(peer1.handshake.remoteMLKEMStatic[:], pubK1)
	mustCopy(peer2.handshake.remoteMLKEMStatic[:], pubK2)

	mustCopy(peer1.handshake.remoteMLDSAStatic[:], pubWrong)

	init, err := dev1.CreateMessageInitiation(peer2)
	if err != nil {
		t.Fatalf("CreateMessageInitiation falhou: %v", err)
	}
	if p := dev2.ConsumeMessageInitiation(init); p != nil {
		t.Fatalf("assinatura inválida deveria falhar")
	}

	mustCopy(peer1.handshake.remoteMLDSAStatic[:], pubGood)
	if p := dev2.ConsumeMessageInitiation(init); p == nil {
		t.Fatalf("deveria aceitar com a pública correta")
	}
	_ = hex.EncodeToString
}
