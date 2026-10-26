/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

//go:build dragonfly

package tun

// DragonFly BSD uses a different _TUNGIFNAME ioctl value than FreeBSD.
const _TUNGIFNAME = 0x40207462
