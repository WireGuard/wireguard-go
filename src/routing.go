package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

type RoutingTable struct {
	IPv4  *Trie
	IPv6  *Trie
	mutex sync.RWMutex
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

func OutgoingRoutingWorker(device *Device, queue chan []byte) {
	for {
		packet := <-queue
		switch packet[0] >> 4 {

		case IPv4version:
			dst := packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
			peer := device.routingTable.LookupIPv4(dst)
			fmt.Println("IPv4", peer)

		case IPv6version:
			dst := packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer := device.routingTable.LookupIPv6(dst)
			fmt.Println("IPv6", peer)

		default:
			// todo: log
			fmt.Println("Unknown IP version")
		}
	}
}
