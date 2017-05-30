package main

import (
	"testing"
)

type testPairCommonBits struct {
	s1    []byte
	s2    []byte
	match uint
}

type testPairTrieInsert struct {
	key  []byte
	cidr uint
	peer *Peer
}

func printTrie(t *testing.T, p *Trie) {
	if p == nil {
		return
	}
	t.Log(p)
	printTrie(t, p.child[0])
	printTrie(t, p.child[1])
}

func TestCommonBits(t *testing.T) {

	tests := []testPairCommonBits{
		{s1: []byte{1, 4, 53, 128}, s2: []byte{0, 0, 0, 0}, match: 7},
		{s1: []byte{0, 4, 53, 128}, s2: []byte{0, 0, 0, 0}, match: 13},
		{s1: []byte{0, 4, 53, 253}, s2: []byte{0, 4, 53, 252}, match: 31},
		{s1: []byte{192, 168, 1, 1}, s2: []byte{192, 169, 1, 1}, match: 15},
		{s1: []byte{65, 168, 1, 1}, s2: []byte{192, 169, 1, 1}, match: 0},
	}

	for _, p := range tests {
		v := commonBits(p.s1, p.s2)
		if v != p.match {
			t.Error(
				"For slice", p.s1, p.s2,
				"expected match", p.match,
				"got", v,
			)
		}
	}
}

func TestTrieInsertV4(t *testing.T) {
	var trie *Trie

	peer1 := Peer{}
	peer2 := Peer{}

	tests := []testPairTrieInsert{
		{key: []byte{192, 168, 1, 1}, cidr: 24, peer: &peer1},
		{key: []byte{192, 169, 1, 1}, cidr: 24, peer: &peer2},
	}

	for _, p := range tests {
		trie = trie.Insert(p.key, p.cidr, p.peer)
		printTrie(t, trie)
	}

}
