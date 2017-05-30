package main

import "fmt"

/* Syncronization must be done seperatly
 *
 */

type Trie struct {
	cidr  uint
	child [2]*Trie
	bits  []byte
	peer  *Peer

	// Index of "branching" bit
	// bit_at_shift
	bit_at_byte  uint
	bit_at_shift uint
}

/* Finds length of matching prefix
 * Maybe there is a faster way
 *
 * Assumption: len(s1) == len(s2)
 */
func commonBits(s1 []byte, s2 []byte) uint {
	var i uint
	size := uint(len(s1))
	for i = 0; i < size; i += 1 {
		v := s1[i] ^ s2[i]
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

	// Walk recursivly

	node.child[0] = node.child[0].RemovePeer(p)
	node.child[1] = node.child[1].RemovePeer(p)

	if node.peer != p {
		return node
	}

	// Remove peer & merge

	node.peer = nil
	if node.child[0] == nil {
		return node.child[1]
	}
	return node.child[0]
}

func (node *Trie) Insert(key []byte, cidr uint, peer *Peer) *Trie {
	if node == nil {
		return &Trie{
			bits:         key,
			peer:         peer,
			cidr:         cidr,
			bit_at_byte:  cidr / 8,
			bit_at_shift: 7 - (cidr % 8),
		}
	}

	// Traverse deeper

	common := commonBits(node.bits, key)
	if node.cidr <= cidr && common >= node.cidr {
		// Check if match the t.bits[:t.cidr] exactly
		if node.cidr == cidr {
			node.peer = peer
			return node
		}

		// Go to child
		bit := (key[node.bit_at_byte] >> node.bit_at_shift) & 1
		node.child[bit] = node.child[bit].Insert(key, cidr, peer)
		return node
	}

	// Split node

	fmt.Println("new", common)

	newNode := &Trie{
		bits:         key,
		peer:         peer,
		cidr:         cidr,
		bit_at_byte:  cidr / 8,
		bit_at_shift: 7 - (cidr % 8),
	}

	cidr = min(cidr, common)
	node.cidr = cidr
	node.bit_at_byte = cidr / 8
	node.bit_at_shift = 7 - (cidr % 8)

	// bval := node.bits[node.bit_at_byte] >> node.bit_at_shift // todo : remember index
	// Work in progress
	node.child[0] = newNode
	node.child[1] = newNode

	return node
}

func (t *Trie) Lookup(key []byte) *Peer {
	if t == nil {
		return nil
	}

	return nil

}
