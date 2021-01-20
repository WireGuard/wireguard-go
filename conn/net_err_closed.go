/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import _ "unsafe"

//TODO: replace this with net.ErrClosed for Go 1.16

//go:linkname NetErrClosed internal/poll.ErrNetClosing
var NetErrClosed error
