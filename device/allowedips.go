/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"unsafe"
)

type ipArray interface {
	[4]byte | [16]byte
}

type parentIndirection[B ipArray] struct {
	parentBit     **trieEntry[B]
	parentBitType uint8
}

type trieEntry[B ipArray] struct {
	peer        *Peer
	child       [2]*trieEntry[B]
	parent      parentIndirection[B]
	cidr        uint8
	bitAtByte   uint8
	bitAtShift  uint8
	bits        B
	perPeerElem *list.Element
}

func commonBits4(ip1, ip2 [4]byte) uint8 {
	a := binary.BigEndian.Uint32(ip1[:])
	b := binary.BigEndian.Uint32(ip2[:])
	x := a ^ b
	return uint8(bits.LeadingZeros32(x))
}

func commonBits16(ip1, ip2 [16]byte) uint8 {
	a := binary.BigEndian.Uint64(ip1[:8])
	b := binary.BigEndian.Uint64(ip2[:8])
	x := a ^ b
	if x != 0 {
		return uint8(bits.LeadingZeros64(x))
	}
	a = binary.BigEndian.Uint64(ip1[8:])
	b = binary.BigEndian.Uint64(ip2[8:])
	x = a ^ b
	return 64 + uint8(bits.LeadingZeros64(x))
}

func giveMeA4[B ipArray](b B) [4]byte {
	return *(*[4]byte)(unsafe.Slice(&b[0], 4))
}

func giveMeA16[B ipArray](b B) [16]byte {
	return *(*[16]byte)(unsafe.Slice(&b[0], 16))
}

func commonBits[B ipArray](ip1, ip2 B) uint8 {
	if len(ip1) == 4 {
		return commonBits4(giveMeA4(ip1), giveMeA4(ip2))
	} else if len(ip1) == 16 {
		return commonBits16(giveMeA16(ip1), giveMeA16(ip2))
	}
	panic("Wrong size bit string")
}

func (node *trieEntry[B]) addToPeerEntries() {
	node.perPeerElem = node.peer.trieEntries.PushBack(node)
}

func (node *trieEntry[B]) removeFromPeerEntries() {
	if node.perPeerElem != nil {
		node.peer.trieEntries.Remove(node.perPeerElem)
		node.perPeerElem = nil
	}
}

func (node *trieEntry[B]) choose(ip B) byte {
	return (ip[node.bitAtByte] >> node.bitAtShift) & 1
}

func (node *trieEntry[B]) maskSelf() {
	mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
	for i := 0; i < len(mask); i++ {
		node.bits[i] &= mask[i]
	}
}

func (node *trieEntry[B]) zeroizePointers() {
	// Make the garbage collector's life slightly easier
	node.peer = nil
	node.child[0] = nil
	node.child[1] = nil
	node.parent.parentBit = nil
}

func (node *trieEntry[B]) nodePlacement(ip B, cidr uint8) (parent *trieEntry[B], exact bool) {
	for node != nil && node.cidr <= cidr && commonBits(node.bits, ip) >= node.cidr {
		parent = node
		if parent.cidr == cidr {
			exact = true
			return
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return
}

func (trie parentIndirection[B]) insert(ip B, cidr uint8, peer *Peer) {
	if *trie.parentBit == nil {
		node := &trieEntry[B]{
			peer:       peer,
			parent:     trie,
			bits:       ip,
			cidr:       cidr,
			bitAtByte:  cidr / 8,
			bitAtShift: 7 - (cidr % 8),
		}
		node.maskSelf()
		node.addToPeerEntries()
		*trie.parentBit = node
		return
	}
	node, exact := (*trie.parentBit).nodePlacement(ip, cidr)
	if exact {
		node.removeFromPeerEntries()
		node.peer = peer
		node.addToPeerEntries()
		return
	}

	newNode := &trieEntry[B]{
		peer:       peer,
		bits:       ip,
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	newNode.maskSelf()
	newNode.addToPeerEntries()

	var down *trieEntry[B]
	if node == nil {
		down = *trie.parentBit
	} else {
		bit := node.choose(ip)
		down = node.child[bit]
		if down == nil {
			newNode.parent = parentIndirection[B]{&node.child[bit], bit}
			node.child[bit] = newNode
			return
		}
	}
	common := commonBits(down.bits, ip)
	if common < cidr {
		cidr = common
	}
	parent := node

	if newNode.cidr == cidr {
		bit := newNode.choose(down.bits)
		down.parent = parentIndirection[B]{&newNode.child[bit], bit}
		newNode.child[bit] = down
		if parent == nil {
			newNode.parent = trie
			*trie.parentBit = newNode
		} else {
			bit := parent.choose(newNode.bits)
			newNode.parent = parentIndirection[B]{&parent.child[bit], bit}
			parent.child[bit] = newNode
		}
		return
	}

	node = &trieEntry[B]{
		bits:       newNode.bits,
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	node.maskSelf()

	bit := node.choose(down.bits)
	down.parent = parentIndirection[B]{&node.child[bit], bit}
	node.child[bit] = down
	bit = node.choose(newNode.bits)
	newNode.parent = parentIndirection[B]{&node.child[bit], bit}
	node.child[bit] = newNode
	if parent == nil {
		node.parent = trie
		*trie.parentBit = node
	} else {
		bit := parent.choose(node.bits)
		node.parent = parentIndirection[B]{&parent.child[bit], bit}
		parent.child[bit] = node
	}
}

func (node *trieEntry[B]) lookup(ip B) *Peer {
	var found *Peer
	size := uint8(len(ip))
	for node != nil && commonBits(node.bits, ip) >= node.cidr {
		if node.peer != nil {
			found = node.peer
		}
		if node.bitAtByte == size {
			break
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return found
}

type AllowedIPs struct {
	IPv4  *trieEntry[[4]byte]
	IPv6  *trieEntry[[16]byte]
	mutex sync.RWMutex
}

func (table *AllowedIPs) EntriesForPeer(peer *Peer, cb func(prefix netip.Prefix) bool) {
	table.mutex.RLock()
	defer table.mutex.RUnlock()

	for elem := peer.trieEntries.Front(); elem != nil; elem = elem.Next() {
		if node, ok := elem.Value.(*trieEntry[[4]byte]); ok {
			if !cb(netip.PrefixFrom(netip.AddrFrom4(node.bits), int(node.cidr))) {
				return
			}
		} else if node, ok := elem.Value.(*trieEntry[[16]byte]); ok {
			if !cb(netip.PrefixFrom(netip.AddrFrom16(node.bits), int(node.cidr))) {
				return
			}
		}
	}
}

func (node *trieEntry[B]) remove() {
	node.removeFromPeerEntries()
	node.peer = nil
	if node.child[0] != nil && node.child[1] != nil {
		return
	}
	bit := 0
	if node.child[0] == nil {
		bit = 1
	}
	child := node.child[bit]
	if child != nil {
		child.parent = node.parent
	}
	*node.parent.parentBit = child
	if node.child[0] != nil || node.child[1] != nil || node.parent.parentBitType > 1 {
		node.zeroizePointers()
		return
	}
	parent := (*trieEntry[B])(unsafe.Pointer(uintptr(unsafe.Pointer(node.parent.parentBit)) - unsafe.Offsetof(node.child) - unsafe.Sizeof(node.child[0])*uintptr(node.parent.parentBitType)))
	if parent.peer != nil {
		node.zeroizePointers()
		return
	}
	child = parent.child[node.parent.parentBitType^1]
	if child != nil {
		child.parent = parent.parent
	}
	*parent.parent.parentBit = child
	node.zeroizePointers()
	parent.zeroizePointers()
}

func (table *AllowedIPs) RemoveByPeer(peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	var next *list.Element
	for elem := peer.trieEntries.Front(); elem != nil; elem = next {
		next = elem.Next()
		if node, ok := elem.Value.(*trieEntry[[4]byte]); ok {
			node.remove()
		} else if node, ok := elem.Value.(*trieEntry[[16]byte]); ok {
			node.remove()
		}
	}
}

func (table *AllowedIPs) Insert(prefix netip.Prefix, peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	if prefix.Addr().Is6() {
		parentIndirection[[16]byte]{&table.IPv6, 2}.insert(prefix.Addr().As16(), uint8(prefix.Bits()), peer)
	} else if prefix.Addr().Is4() {
		parentIndirection[[4]byte]{&table.IPv4, 2}.insert(prefix.Addr().As4(), uint8(prefix.Bits()), peer)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}

func (table *AllowedIPs) Lookup(ip []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	switch len(ip) {
	case net.IPv6len:
		return table.IPv6.lookup(*(*[16]byte)(ip))
	case net.IPv4len:
		return table.IPv4.lookup(*(*[4]byte)(ip))
	default:
		panic(errors.New("looking up unknown address type"))
	}
}
