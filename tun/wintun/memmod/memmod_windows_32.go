// +build 386 arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package memmod

func (opthdr *IMAGE_OPTIONAL_HEADER) imageOffset() uintptr {
	return 0
}

func (module *Module) check4GBBoundaries(alignedImageSize uintptr) (err error) {
	return
}
