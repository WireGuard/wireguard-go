/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"math/bits"
	"net"
	"sync"
	"unsafe"
)

type trieEntry struct {
	cidr  uint
	child [2]*trieEntry
	bits  net.IP
	peer  *Peer

	// index of "branching" bit

	bit_at_byte  uint
	bit_at_shift uint
}

func isLittleEndian() bool {
	one := uint32(1)
	return *(*byte)(unsafe.Pointer(&one)) != 0
}

func swapU32(i uint32) uint32 {
	if !isLittleEndian() {
		return i
	}

	return bits.ReverseBytes32(i)
}

func swapU64(i uint64) uint64 {
	if !isLittleEndian() {
		return i
	}

	return bits.ReverseBytes64(i)
}

func commonBits(ip1 net.IP, ip2 net.IP) uint {
	size := len(ip1)
	if size == net.IPv4len {
		a := (*uint32)(unsafe.Pointer(&ip1[0]))
		b := (*uint32)(unsafe.Pointer(&ip2[0]))
		x := *a ^ *b
		return uint(bits.LeadingZeros32(swapU32(x)))
	} else if size == net.IPv6len {
		a := (*uint64)(unsafe.Pointer(&ip1[0]))
		b := (*uint64)(unsafe.Pointer(&ip2[0]))
		x := *a ^ *b
		if x != 0 {
			return uint(bits.LeadingZeros64(swapU64(x)))
		}
		a = (*uint64)(unsafe.Pointer(&ip1[8]))
		b = (*uint64)(unsafe.Pointer(&ip2[8]))
		x = *a ^ *b
		return 64 + uint(bits.LeadingZeros64(swapU64(x)))
	} else {
		panic("Wrong size bit string")
	}
}

func (node *trieEntry) removeByPeer(p *Peer) *trieEntry {
	if node == nil {
		return node
	}

	// walk recursively

	node.child[0] = node.child[0].removeByPeer(p)
	node.child[1] = node.child[1].removeByPeer(p)

	if node.peer != p {
		return node
	}

	// remove peer & merge

	node.peer = nil
	if node.child[0] == nil {
		return node.child[1]
	}
	return node.child[0]
}

func (node *trieEntry) choose(ip net.IP) byte {
	return (ip[node.bit_at_byte] >> node.bit_at_shift) & 1
}

func (node *trieEntry) insert(ip net.IP, cidr uint, peer *Peer) *trieEntry {

	// at leaf

	if node == nil {
		return &trieEntry{
			bits:         ip,
			peer:         peer,
			cidr:         cidr,
			bit_at_byte:  cidr / 8,
			bit_at_shift: 7 - (cidr % 8),
		}
	}

	// traverse deeper

	common := commonBits(node.bits, ip)
	if node.cidr <= cidr && common >= node.cidr {
		if node.cidr == cidr {
			node.peer = peer
			return node
		}
		bit := node.choose(ip)
		node.child[bit] = node.child[bit].insert(ip, cidr, peer)
		return node
	}

	// split node

	newNode := &trieEntry{
		bits:         ip,
		peer:         peer,
		cidr:         cidr,
		bit_at_byte:  cidr / 8,
		bit_at_shift: 7 - (cidr % 8),
	}

	cidr = min(cidr, common)

	// check for shorter prefix

	if newNode.cidr == cidr {
		bit := newNode.choose(node.bits)
		newNode.child[bit] = node
		return newNode
	}

	// create new parent for node & newNode

	parent := &trieEntry{
		bits:         ip,
		peer:         nil,
		cidr:         cidr,
		bit_at_byte:  cidr / 8,
		bit_at_shift: 7 - (cidr % 8),
	}

	bit := parent.choose(ip)
	parent.child[bit] = newNode
	parent.child[bit^1] = node

	return parent
}

func (node *trieEntry) lookup(ip net.IP) *Peer {
	var found *Peer
	size := uint(len(ip))
	for node != nil && commonBits(node.bits, ip) >= node.cidr {
		if node.peer != nil {
			found = node.peer
		}
		if node.bit_at_byte == size {
			break
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return found
}

func (node *trieEntry) entriesForPeer(p *Peer, results []net.IPNet) []net.IPNet {
	if node == nil {
		return results
	}
	if node.peer == p {
		mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
		results = append(results, net.IPNet{
			Mask: mask,
			IP:   node.bits.Mask(mask),
		})
	}
	results = node.child[0].entriesForPeer(p, results)
	results = node.child[1].entriesForPeer(p, results)
	return results
}

type AllowedIPs struct {
	IPv4  *trieEntry
	IPv6  *trieEntry
	mutex sync.RWMutex
}

func (table *AllowedIPs) EntriesForPeer(peer *Peer) []net.IPNet {
	table.mutex.RLock()
	defer table.mutex.RUnlock()

	allowed := make([]net.IPNet, 0, 10)
	allowed = table.IPv4.entriesForPeer(peer, allowed)
	allowed = table.IPv6.entriesForPeer(peer, allowed)
	return allowed
}

func (table *AllowedIPs) Reset() {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.IPv4 = nil
	table.IPv6 = nil
}

func (table *AllowedIPs) RemoveByPeer(peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.IPv4 = table.IPv4.removeByPeer(peer)
	table.IPv6 = table.IPv6.removeByPeer(peer)
}

func (table *AllowedIPs) Insert(ip net.IP, cidr uint, peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	switch len(ip) {
	case net.IPv6len:
		table.IPv6 = table.IPv6.insert(ip, cidr, peer)
	case net.IPv4len:
		table.IPv4 = table.IPv4.insert(ip, cidr, peer)
	default:
		panic(errors.New("inserting unknown address type"))
	}
}

func (table *AllowedIPs) Any() *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	matchAny := func(entry *trieEntry) bool {
		for _, b := range entry.bits {
			if b != 0 {
				return false
			}
		}
		return true
	}
	if p := findPeer(table.IPv4, matchAny); p != nil {
		return p
	}
	return findPeer(table.IPv6, matchAny)
}

func findPeer(t *trieEntry, match func(*trieEntry) bool) *Peer {
	if t == nil {
		return nil
	}
	if match(t) && t.peer != nil {
		return t.peer
	}
	result := findPeer(t.child[0], match)
	if result != nil {
		return result
	}
	return findPeer(t.child[1], match)
}

func (table *AllowedIPs) LookupIPv4(address []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.IPv4.lookup(address)
}

func (table *AllowedIPs) LookupIPv6(address []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.IPv6.lookup(address)
}
