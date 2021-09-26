//go:build !windows && !linux
// +build !windows,!linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package rwcancel

import "golang.org/x/sys/unix"

func poll(fds []unix.PollFd, timeout int) (n int, err error) {
	return unix.Poll(fds, timeout)
}
