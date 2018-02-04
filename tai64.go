package main

import (
	"bytes"
	"encoding/binary"
	"time"
)

const (
	TAI64NBase = uint64(4611686018427387914)
	TAI64NSize = 12
)

type TAI64N [TAI64NSize]byte

func Timestamp() TAI64N {
	var tai64n TAI64N
	now := time.Now()
	secs := TAI64NBase + uint64(now.Unix())
	nano := uint32(now.UnixNano())
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

func (t1 *TAI64N) After(t2 TAI64N) bool {
	return bytes.Compare(t1[:], t2[:]) > 0
}
