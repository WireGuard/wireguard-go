/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package replay implements an efficient anti-replay algorithm as specified in RFC 6479.
package replay

type block uint64

const (
	blockBitLog  = 6 // 1<<6 == 64 bits
	ringBlockLog = 7
	blockBits    = 1 << blockBitLog  // must be power of 2
	ringBlocks   = 1 << ringBlockLog // must be power of 2
	windowSize   = (ringBlocks - 1) * blockBits
	blockMask    = ringBlocks - 1
	blockMaskV2  = (ringBlocks << 1) - 1
	bitMask      = blockBits - 1
)

// A Filter rejects replayed messages by checking if message counter value is
// within a sliding window of previously received messages.
// The zero value for Filter is an empty filter ready to use.
// Filters are unsafe for concurrent use.
type Filter struct {
	last uint64
	ring [ringBlocks]block
}

// Reset resets the filter to empty state.
func (f *Filter) Reset() {
	f.last = 0
	f.ring[0] = 0
}

// ValidateCounter checks if the counter should be accepted.
// Overlimit counters (>= limit) are always rejected.
func (f *Filter) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}
	indexBlock := counter >> blockBitLog
	if counter > f.last { // move window forward
		current := f.last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks // cap diff to clear the whole ring
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&blockMask] = 0
		}
		f.last = counter
	} else if f.last-counter > windowSize { // behind current window
		return false
	}
	// check and set bit
	indexBlock &= blockMask
	indexBit := counter & bitMask
	old := f.ring[indexBlock]
	new := old | 1<<indexBit
	f.ring[indexBlock] = new
	return old != new
}

type FilterV2 struct {
	last       uint64
	clearPoint uint64
	ring       [ringBlocks * 2]block
}

func NewFilterV2() FilterV2 {
	filter := FilterV2{}
	filter.clearPoint = 2 * ringBlocks
	return filter
}

// Reset resets the filter to empty state.
func (f *FilterV2) Reset() {
	f.last = 0
	clear(f.ring[:])
}

func (f *FilterV2) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}
	indexBlock := counter >> blockBitLog

	if counter > f.last {
		f.last = counter
	} else if f.last-counter > windowSize { // behind current window
		return false
	}

	if indexBlock >= f.clearPoint {
		if indexBlock-f.clearPoint >= ringBlocks {
			// Jump spans a full half or more: every slot is stale.
			clear(f.ring[:])
		} else {
			// Clear the half being entered; the other half still holds
			// the live window bits.
			off := (indexBlock >> ringBlockLog & 1) << ringBlockLog
			clear(f.ring[off : off+ringBlocks])
		}
		f.clearPoint = (indexBlock>>ringBlockLog + 1) << ringBlockLog
	}

	// check and set bit
	indexBlock &= blockMaskV2
	indexBit := counter & bitMask
	old := f.ring[indexBlock]
	new := old | 1<<indexBit
	f.ring[indexBlock] = new
	return old != new
}
