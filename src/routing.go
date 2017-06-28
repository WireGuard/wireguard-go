package main

import (
	"errors"
	"net"
	"sync"
)

type RoutingTable struct {
	IPv4  *Trie
	IPv6  *Trie
	mutex sync.RWMutex
}

func (table *RoutingTable) AllowedIPs(peer *Peer) []net.IPNet {
	table.mutex.RLock()
	defer table.mutex.RUnlock()

	allowed := make([]net.IPNet, 10)
	table.IPv4.AllowedIPs(peer, allowed)
	table.IPv6.AllowedIPs(peer, allowed)
	return allowed
}

func (table *RoutingTable) Reset() {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.IPv4 = nil
	table.IPv6 = nil
}

func (table *RoutingTable) RemovePeer(peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.IPv4 = table.IPv4.RemovePeer(peer)
	table.IPv6 = table.IPv6.RemovePeer(peer)
}

func (table *RoutingTable) Insert(ip net.IP, cidr uint, peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	switch len(ip) {
	case net.IPv6len:
		table.IPv6 = table.IPv6.Insert(ip, cidr, peer)
	case net.IPv4len:
		table.IPv4 = table.IPv4.Insert(ip, cidr, peer)
	default:
		panic(errors.New("Inserting unknown address type"))
	}
}

func (table *RoutingTable) LookupIPv4(address []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.IPv4.Lookup(address)
}

func (table *RoutingTable) LookupIPv6(address []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.IPv6.Lookup(address)
}
