// +build !linux,!openbsd,!freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package main

func (bind *NativeBind) SetMark(mark uint32) error {
	return nil
}
