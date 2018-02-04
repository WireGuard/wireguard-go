package main

import (
	"errors"
	"net"
)

/* Binary trie
 *
 * The net.IPs used here are not formatted the
 * same way as those created by the "net" functions.
 * Here the IPs are slices of either 4 or 16 byte (not always 16)
 *
 * Synchronization done separately
 * See: routing.go
 */

type Trie struct {
	cidr  uint
	child [2]*Trie
	bits  []byte
	peer  *Peer

	// index of "branching" bit

	bit_at_byte  uint
	bit_at_shift uint
}

/* Finds length of matching prefix
 *
 * TODO: Only use during insertion (xor + prefix mask for lookup)
 *       Check out
 *       prefix_matches(struct allowedips_node *node, const u8 *key, u8 bits)
 *       https://git.zx2c4.com/WireGuard/commit/?h=jd/precomputed-prefix-match
 *
 * Assumption:
 *	  len(ip1) == len(ip2)
 *	  len(ip1) mod 4 = 0
 */
func commonBits(ip1 []byte, ip2 []byte) uint {
	var i uint
	size := uint(len(ip1))

	for i = 0; i < size; i++ {
		v := ip1[i] ^ ip2[i]
		if v != 0 {
			v >>= 1
			if v == 0 {
				return i*8 + 7
			}

			v >>= 1
			if v == 0 {
				return i*8 + 6
			}

			v >>= 1
			if v == 0 {
				return i*8 + 5
			}

			v >>= 1
			if v == 0 {
				return i*8 + 4
			}

			v >>= 1
			if v == 0 {
				return i*8 + 3
			}

			v >>= 1
			if v == 0 {
				return i*8 + 2
			}

			v >>= 1
			if v == 0 {
				return i*8 + 1
			}
			return i * 8
		}
	}
	return i * 8
}

func (node *Trie) RemovePeer(p *Peer) *Trie {
	if node == nil {
		return node
	}

	// walk recursively

	node.child[0] = node.child[0].RemovePeer(p)
	node.child[1] = node.child[1].RemovePeer(p)

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

func (node *Trie) choose(ip net.IP) byte {
	return (ip[node.bit_at_byte] >> node.bit_at_shift) & 1
}

func (node *Trie) Insert(ip net.IP, cidr uint, peer *Peer) *Trie {

	// at leaf

	if node == nil {
		return &Trie{
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
		node.child[bit] = node.child[bit].Insert(ip, cidr, peer)
		return node
	}

	// split node

	newNode := &Trie{
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

	parent := &Trie{
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

func (node *Trie) Lookup(ip net.IP) *Peer {
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

func (node *Trie) Count() uint {
	if node == nil {
		return 0
	}
	l := node.child[0].Count()
	r := node.child[1].Count()
	return l + r
}

func (node *Trie) AllowedIPs(p *Peer, results []net.IPNet) []net.IPNet {
	if node == nil {
		return results
	}
	if node.peer == p {
		var mask net.IPNet
		mask.Mask = net.CIDRMask(int(node.cidr), len(node.bits)*8)
		if len(node.bits) == net.IPv4len {
			mask.IP = net.IPv4(
				node.bits[0],
				node.bits[1],
				node.bits[2],
				node.bits[3],
			)
		} else if len(node.bits) == net.IPv6len {
			mask.IP = node.bits
		} else {
			panic(errors.New("bug: unexpected address length"))
		}
		results = append(results, mask)
	}
	results = node.child[0].AllowedIPs(p, results)
	results = node.child[1].AllowedIPs(p, results)
	return results
}
