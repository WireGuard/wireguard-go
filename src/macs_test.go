package main

import (
	"bytes"
	"net"
	"testing"
	"testing/quick"
)

func TestMAC1(t *testing.T) {
	dev1 := newDevice(t)
	dev2 := newDevice(t)

	peer1 := dev2.NewPeer(dev1.privateKey.publicKey())
	peer2 := dev1.NewPeer(dev2.privateKey.publicKey())

	assertEqual(t, peer1.mac.keyMac1[:], dev1.mac.keyMac1[:])
	assertEqual(t, peer2.mac.keyMac1[:], dev2.mac.keyMac1[:])

	msg1 := make([]byte, 256)
	copy(msg1, []byte("some content"))
	peer1.mac.AddMacs(msg1)
	if dev1.mac.CheckMAC1(msg1) == false {
		t.Fatal("failed to verify mac1")
	}
}

func TestMACs(t *testing.T) {
	assertion := func(
		addr net.UDPAddr,
		addrInvalid net.UDPAddr,
		sk1 NoisePrivateKey,
		sk2 NoisePrivateKey,
		msg []byte,
		receiver uint32,
	) bool {
		var device1 Device
		device1.Init()
		device1.SetPrivateKey(sk1)

		var device2 Device
		device2.Init()
		device2.SetPrivateKey(sk2)

		peer1 := device2.NewPeer(device1.privateKey.publicKey())
		peer2 := device1.NewPeer(device2.privateKey.publicKey())

		if addr.Port < 0 {
			return true
		}
		addr.Port &= 0xffff

		if len(msg) < 32 {
			return true
		}
		if bytes.Compare(peer1.mac.keyMac1[:], device1.mac.keyMac1[:]) != 0 {
			return false
		}
		if bytes.Compare(peer2.mac.keyMac1[:], device2.mac.keyMac1[:]) != 0 {
			return false
		}

		device2.indices.Insert(receiver, IndexTableEntry{
			peer:      peer1,
			handshake: &peer1.handshake,
		})

		// test just MAC1

		peer1.mac.AddMacs(msg)
		if device1.mac.CheckMAC1(msg) == false {
			return false
		}

		// exchange cookie reply

		cr, err := device1.CreateMessageCookieReply(msg, receiver, &addr)
		if err != nil {
			return false
		}

		if device2.ConsumeMessageCookieReply(cr) == false {
			return false
		}

		// test MAC1 + MAC2

		peer1.mac.AddMacs(msg)
		if device1.mac.CheckMAC1(msg) == false {
			return false
		}
		if device1.mac.CheckMAC2(msg, &addr) == false {
			return false
		}

		// test invalid

		if device1.mac.CheckMAC2(msg, &addrInvalid) {
			return false
		}
		msg[5] ^= 1
		if device1.mac.CheckMAC1(msg) {
			return false
		}

		return true
	}

	err := quick.Check(assertion, nil)
	if err != nil {
		t.Error(err)
	}
}
