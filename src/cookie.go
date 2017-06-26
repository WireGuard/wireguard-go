package main

import (
	"errors"
	"golang.org/x/crypto/blake2s"
)

func CalculateCookie(peer *Peer, msg []byte) {
	size := len(msg)

	if size < blake2s.Size128*2 {
		panic(errors.New("bug: message too short"))
	}

	startMac1 := size - (blake2s.Size128 * 2)
	startMac2 := size - blake2s.Size128

	mac1 := msg[startMac1 : startMac1+blake2s.Size128]
	mac2 := msg[startMac2 : startMac2+blake2s.Size128]

	peer.mutex.RLock()
	defer peer.mutex.RUnlock()

	// set mac1

	func() {
		mac, _ := blake2s.New128(peer.macKey[:])
		mac.Write(msg[:startMac1])
		mac.Sum(mac1[:0])
	}()

	// set mac2

	if peer.cookie != nil {
		mac, _ := blake2s.New128(peer.cookie)
		mac.Write(msg[:startMac2])
		mac.Sum(mac2[:0])
	}
}
