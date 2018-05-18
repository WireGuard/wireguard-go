/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

package main

/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

/* Implementation of RFC6479
 * https://tools.ietf.org/html/rfc6479
 *
 * The implementation is not safe for concurrent use!
 */

const (
	// See: https://golang.org/src/math/big/arith.go
	_Wordm       = ^uintptr(0)
	_WordLogSize = _Wordm>>8&1 + _Wordm>>16&1 + _Wordm>>32&1
	_WordSize    = 1 << _WordLogSize
)

const (
	CounterRedundantBitsLog = _WordLogSize + 3
	CounterRedundantBits    = _WordSize * 8
	CounterBitsTotal        = 2048
	CounterWindowSize       = uint64(CounterBitsTotal - CounterRedundantBits)
)

const (
	BacktrackWords = CounterBitsTotal / _WordSize
)

type ReplayFilter struct {
	counter   uint64
	backtrack [BacktrackWords]uintptr
}

func (filter *ReplayFilter) Init() {
	filter.counter = 0
	filter.backtrack[0] = 0
}

func (filter *ReplayFilter) ValidateCounter(counter uint64) bool {
	if counter >= RejectAfterMessages {
		return false
	}

	indexWord := counter >> CounterRedundantBitsLog

	if counter > filter.counter {

		// move window forward

		current := filter.counter >> CounterRedundantBitsLog
		diff := minUint64(indexWord-current, BacktrackWords)
		for i := uint64(1); i <= diff; i++ {
			filter.backtrack[(current+i)%BacktrackWords] = 0
		}
		filter.counter = counter

	} else if filter.counter-counter > CounterWindowSize {

		// behind current window

		return false
	}

	indexWord %= BacktrackWords
	indexBit := counter & uint64(CounterRedundantBits-1)

	// check and set bit

	oldValue := filter.backtrack[indexWord]
	newValue := oldValue | (1 << indexBit)
	filter.backtrack[indexWord] = newValue
	return oldValue != newValue
}
