/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/* Types to deal with FreeBSD fdiogname ioctl for determining tun device name */

package main

// Iface name max len
const _IFNAMESIZ = 16

// structure for iface requests with a pointer
type ifreq_ptr struct {
	Name [_IFNAMESIZ]byte
	Data uintptr
	Pad0 [16]byte
}
