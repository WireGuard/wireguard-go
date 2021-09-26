/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package rwcancel

import "golang.org/x/sys/unix"

func poll(fds []unix.PollFd, timeout int) (n int, err error) {
	var ts *unix.Timespec
	if timeout >= 0 {
		ts = new(unix.Timespec)
		*ts = unix.NsecToTimespec(int64(timeout) * 1e6)
	}
	return unix.Ppoll(fds, ts, nil)
}
