package main

import (
	"testing"
)

func TestHandshake(t *testing.T) {
	var dev1 Device
	var dev2 Device

	var err error

	dev1.privateKey, err = newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	dev2.privateKey, err = newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	var peer1 Peer
	var peer2 Peer

	peer1.publicKey = dev1.privateKey.publicKey()
	peer2.publicKey = dev2.privateKey.publicKey()

	var handshake1 Handshake
	var handshake2 Handshake

	handshake1.device = &dev1
	handshake2.device = &dev2

	handshake1.peer = &peer2
	handshake2.peer = &peer1

}
