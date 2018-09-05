/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"crypto/rand"
	"sync"
	"unsafe"
)

type IndexTableEntry struct {
	peer      *Peer
	handshake *Handshake
	keypair   *Keypair
}

type IndexTable struct {
	mutex sync.RWMutex
	table map[uint32]IndexTableEntry
}

func randUint32() (uint32, error) {
	var integer [4]byte
	_, err := rand.Read(integer[:])
	return *(*uint32)(unsafe.Pointer(&integer[0])), err
}

func (table *IndexTable) Init() {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	table.table = make(map[uint32]IndexTableEntry)
}

func (table *IndexTable) Delete(index uint32) {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	delete(table.table, index)
}

func (table *IndexTable) SwapIndexForKeypair(index uint32, keypair *Keypair) {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	entry, ok := table.table[index]
	if !ok {
		return
	}
	table.table[index] = IndexTableEntry{
		peer:      entry.peer,
		keypair:   keypair,
		handshake: nil,
	}
}

func (table *IndexTable) NewIndexForHandshake(peer *Peer, handshake *Handshake) (uint32, error) {
	for {
		// generate random index

		index, err := randUint32()
		if err != nil {
			return index, err
		}

		// check if index used

		table.mutex.RLock()
		_, ok := table.table[index]
		table.mutex.RUnlock()
		if ok {
			continue
		}

		// check again while locked

		table.mutex.Lock()
		_, found := table.table[index]
		if found {
			table.mutex.Unlock()
			continue
		}
		table.table[index] = IndexTableEntry{
			peer:      peer,
			handshake: handshake,
			keypair:   nil,
		}
		table.mutex.Unlock()
		return index, nil
	}
}

func (table *IndexTable) Lookup(id uint32) IndexTableEntry {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	return table.table[id]
}
