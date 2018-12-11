/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package rwcancel

import "golang.org/x/sys/unix"

type fdSet struct {
	fdset unix.FdSet
}

func (fdset *fdSet) set(i int) {
	bits := 32 << (^uint(0) >> 63)
	fdset.fdset.Bits[i/bits] |= 1 << uint(i%bits)
}

func (fdset *fdSet) check(i int) bool {
	bits := 32 << (^uint(0) >> 63)
	return (fdset.fdset.Bits[i/bits] & (1 << uint(i%bits))) != 0
}
