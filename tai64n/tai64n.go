/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const TimestampSize = 12
const base = uint64(0x400000000000000a)
const whitenerMask = uint32(0x1000000 - 1)

type Timestamp [TimestampSize]byte

func Now() Timestamp {
	var tai64n Timestamp
	now := time.Now()
	secs := base + uint64(now.Unix())
	nano := uint32(now.Nanosecond()) &^ whitenerMask
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

func (t1 Timestamp) After(t2 Timestamp) bool {
	return bytes.Compare(t1[:], t2[:]) > 0
}
