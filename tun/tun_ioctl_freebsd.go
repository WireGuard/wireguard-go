/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

//go:build freebsd

package tun

// _TUNGIFNAME differs between FreeBSD and DragonFly BSD.
const _TUNGIFNAME = 0x4020745d
