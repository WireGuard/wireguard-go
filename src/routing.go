package main

import (
	"sync"
)

/* Thread-safe high level functions for cryptkey routing.
 *
 */

type RoutingTable struct {
	IPv4  *Trie
	IPv6  *Trie
	mutex sync.RWMutex
}

func (table *RoutingTable) RemovePeer(peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	table.IPv4 = table.IPv4.RemovePeer(peer)
	table.IPv6 = table.IPv6.RemovePeer(peer)
}
