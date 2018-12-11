// +build !linux,!openbsd,!freebsd

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

func (bind *NativeBind) SetMark(mark uint32) error {
	return nil
}
