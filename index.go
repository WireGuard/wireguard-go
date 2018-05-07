/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

/* Index=0 is reserved for unset indecies
 *
 */

type IndexTableEntry struct {
	peer      *Peer
	handshake *Handshake
	keyPair   *Keypair
}

type IndexTable struct {
	mutex sync.RWMutex
	table map[uint32]IndexTableEntry
}

func randUint32() (uint32, error) {
	var buff [4]byte
	_, err := rand.Read(buff[:])
	value := binary.LittleEndian.Uint32(buff[:])
	return value, err
}

func (table *IndexTable) Init() {
	table.mutex.Lock()
	table.table = make(map[uint32]IndexTableEntry)
	table.mutex.Unlock()
}

func (table *IndexTable) Delete(index uint32) {
	if index == 0 {
		return
	}
	table.mutex.Lock()
	delete(table.table, index)
	table.mutex.Unlock()
}

func (table *IndexTable) Insert(key uint32, value IndexTableEntry) {
	table.mutex.Lock()
	table.table[key] = value
	table.mutex.Unlock()
}

func (table *IndexTable) NewIndex(peer *Peer) (uint32, error) {
	for {
		// generate random index

		index, err := randUint32()
		if err != nil {
			return index, err
		}
		if index == 0 {
			continue
		}

		// check if index used

		table.mutex.RLock()
		_, ok := table.table[index]
		table.mutex.RUnlock()
		if ok {
			continue
		}

		// map index to handshake

		table.mutex.Lock()
		_, found := table.table[index]
		if found {
			table.mutex.Unlock()
			continue
		}
		table.table[index] = IndexTableEntry{
			peer:      peer,
			handshake: &peer.handshake,
			keyPair:   nil,
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
