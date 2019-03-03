/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"math/rand"
	"sort"
	"testing"
)

const (
	NumberOfPeers     = 100
	NumberOfAddresses = 250
	NumberOfTests     = 10000
)

type SlowNode struct {
	peer *Peer
	cidr uint
	bits []byte
}

type SlowRouter []*SlowNode

func (r SlowRouter) Len() int {
	return len(r)
}

func (r SlowRouter) Less(i, j int) bool {
	return r[i].cidr > r[j].cidr
}

func (r SlowRouter) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r SlowRouter) Insert(addr []byte, cidr uint, peer *Peer) SlowRouter {
	for _, t := range r {
		if t.cidr == cidr && commonBits(t.bits, addr) >= cidr {
			t.peer = peer
			t.bits = addr
			return r
		}
	}
	r = append(r, &SlowNode{
		cidr: cidr,
		bits: addr,
		peer: peer,
	})
	sort.Sort(r)
	return r
}

func (r SlowRouter) Lookup(addr []byte) *Peer {
	for _, t := range r {
		common := commonBits(t.bits, addr)
		if common >= t.cidr {
			return t.peer
		}
	}
	return nil
}

func TestTrieRandomIPv4(t *testing.T) {
	var trie *trieEntry
	var slow SlowRouter
	var peers []*Peer

	rand.Seed(1)

	const AddressLength = 4

	for n := 0; n < NumberOfPeers; n += 1 {
		peers = append(peers, &Peer{})
	}

	for n := 0; n < NumberOfAddresses; n += 1 {
		var addr [AddressLength]byte
		rand.Read(addr[:])
		cidr := uint(rand.Uint32() % (AddressLength * 8))
		index := rand.Int() % NumberOfPeers
		trie = trie.insert(addr[:], cidr, peers[index])
		slow = slow.Insert(addr[:], cidr, peers[index])
	}

	for n := 0; n < NumberOfTests; n += 1 {
		var addr [AddressLength]byte
		rand.Read(addr[:])
		peer1 := slow.Lookup(addr[:])
		peer2 := trie.lookup(addr[:])
		if peer1 != peer2 {
			t.Error("Trie did not match naive implementation, for:", addr)
		}
	}
}

func TestTrieRandomIPv6(t *testing.T) {
	var trie *trieEntry
	var slow SlowRouter
	var peers []*Peer

	rand.Seed(1)

	const AddressLength = 16

	for n := 0; n < NumberOfPeers; n += 1 {
		peers = append(peers, &Peer{})
	}

	for n := 0; n < NumberOfAddresses; n += 1 {
		var addr [AddressLength]byte
		rand.Read(addr[:])
		cidr := uint(rand.Uint32() % (AddressLength * 8))
		index := rand.Int() % NumberOfPeers
		trie = trie.insert(addr[:], cidr, peers[index])
		slow = slow.Insert(addr[:], cidr, peers[index])
	}

	for n := 0; n < NumberOfTests; n += 1 {
		var addr [AddressLength]byte
		rand.Read(addr[:])
		peer1 := slow.Lookup(addr[:])
		peer2 := trie.lookup(addr[:])
		if peer1 != peer2 {
			t.Error("Trie did not match naive implementation, for:", addr)
		}
	}
}
