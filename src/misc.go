package main

import (
	"sync/atomic"
)

/* Atomic Boolean */

const (
	AtomicFalse = int32(iota)
	AtomicTrue
)

type AtomicBool struct {
	flag int32
}

func (a *AtomicBool) Get() bool {
	return atomic.LoadInt32(&a.flag) == AtomicTrue
}

func (a *AtomicBool) Swap(val bool) bool {
	flag := AtomicFalse
	if val {
		flag = AtomicTrue
	}
	return atomic.SwapInt32(&a.flag, flag) == AtomicTrue
}

func (a *AtomicBool) Set(val bool) {
	flag := AtomicFalse
	if val {
		flag = AtomicTrue
	}
	atomic.StoreInt32(&a.flag, flag)
}

/* Integer manipulation */

func toInt32(n uint32) int32 {
	mask := uint32(1 << 31)
	return int32(-(n & mask) + (n & ^mask))
}

func min(a uint, b uint) uint {
	if a > b {
		return b
	}
	return a
}

func minUint64(a uint64, b uint64) uint64 {
	if a > b {
		return b
	}
	return a
}
