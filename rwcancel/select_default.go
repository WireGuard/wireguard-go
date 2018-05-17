/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

// +build !linux

package rwcancel

import "golang.org/x/sys/unix"

func unixSelect(nfd int, r *unix.FdSet, w *unix.FdSet, e *unix.FdSet, timeout *unix.Timeval) error {
	return unix.Select(nfd, r, w, e, timeout)
}
