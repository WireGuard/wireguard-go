/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const TimestampSize = 12
const base = uint64(4611686018427387914)

type Timestamp [TimestampSize]byte

func Now() Timestamp {
	var tai64n Timestamp
	now := time.Now()
	secs := base + uint64(now.Unix())
	nano := uint32(now.Nanosecond())
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

func (t1 Timestamp) After(t2 Timestamp) bool {
	return bytes.Compare(t1[:], t2[:]) > 0
}
