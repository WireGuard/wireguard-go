/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
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
	for i := 0; i < 50; i++ {
		next := Now()
		if next.After(old) {
			t.Error("Whitening insufficient")
		}
		time.Sleep(time.Duration(whitenerMask)/time.Nanosecond + 1)
		next = Now()
		if !next.After(old) {
			t.Error("Not monotonically increasing on whitened nano-second scale")
		}
		old = next
	}
}
