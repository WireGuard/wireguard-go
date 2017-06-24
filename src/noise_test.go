package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a []byte, b []byte) {
	if bytes.Compare(a, b) != 0 {
		t.Fatal(a, "!=", b)
	}
}

func TestCurveWrappers(t *testing.T) {
	sk1, err := newPrivateKey()
	assertNil(t, err)

	sk2, err := newPrivateKey()
	assertNil(t, err)

	pk1 := sk1.publicKey()
	pk2 := sk2.publicKey()

	ss1 := sk1.sharedSecret(pk2)
	ss2 := sk2.sharedSecret(pk1)

	if ss1 != ss2 {
		t.Fatal("Failed to compute shared secet")
	}
}

func newDevice(t *testing.T) *Device {
	var device Device
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	device.Init()
	device.SetPrivateKey(sk)
	return &device
}

func TestNoiseHandshake(t *testing.T) {

	dev1 := newDevice(t)
	dev2 := newDevice(t)

	peer1 := dev2.NewPeer(dev1.privateKey.publicKey())
	peer2 := dev1.NewPeer(dev2.privateKey.publicKey())

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// Initiation message

	msg1, err := dev1.CreateMessageInitial(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	peer := dev2.ConsumeMessageInitial(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// Response message

}
