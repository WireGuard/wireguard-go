// +build !linux,!openbsd,!freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package conn

func (bind *nativeBind) SetMark(mark uint32) error {
	return nil
}
