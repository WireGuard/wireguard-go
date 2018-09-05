/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"testing"
	"time"
)

/* Testing the essential property of the timestamp
 * as used by WireGuard.
 */
func TestMonotonic(t *testing.T) {
	old := Now()
	for i := 0; i < 10000; i++ {
		time.Sleep(time.Nanosecond)
		next := Now()
		if !next.After(old) {
			t.Error("TAI64N, not monotonically increasing on nano-second scale")
		}
		old = next
	}
}
