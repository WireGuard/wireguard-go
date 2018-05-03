/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
)

func Warning() {
	shouldQuit := os.Getenv("WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD") != "1"

	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "W   This is alpha software. It will very likely not   G")
	fmt.Fprintln(os.Stderr, "W   do what it is supposed to do, and things may go   G")
	fmt.Fprintln(os.Stderr, "W   horribly wrong. You have been warned. Proceed     G")
	fmt.Fprintln(os.Stderr, "W   at your own risk.                                 G")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "W   Furthermore, you are running this software on a   G")
	fmt.Fprintln(os.Stderr, "W   Linux kernel, which is probably unnecessary and   G")
	fmt.Fprintln(os.Stderr, "W   foolish. This is because the Linux kernel has     G")
	fmt.Fprintln(os.Stderr, "W   built-in first class support for WireGuard, and   G")
	fmt.Fprintln(os.Stderr, "W   this support is much more refined than this       G")
	fmt.Fprintln(os.Stderr, "W   program. For more information on installing the   G")
	fmt.Fprintln(os.Stderr, "W   kernel module, please visit:                      G")
	fmt.Fprintln(os.Stderr, "W           https://www.wireguard.com/install         G")
	if shouldQuit {
		fmt.Fprintln(os.Stderr, "W                                                     G")
		fmt.Fprintln(os.Stderr, "W   If you still want to use this program, against    G")
		fmt.Fprintln(os.Stderr, "W   the sage advice here, please first export this    G")
		fmt.Fprintln(os.Stderr, "W   environment variable:                             G")
		fmt.Fprintln(os.Stderr, "W   WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1    G")
	}
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")

	if shouldQuit {
		os.Exit(1)
	}
}
