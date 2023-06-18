//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import "golang.zx2c4.com/wireguard/conn"

const (
	QueueStagedSize            = conn.IdealBatchSize
	QueueOutboundSize          = 1024
	QueueInboundSize           = 1024
	QueueHandshakeSize         = 1024
	MaxSegmentSize             = (1 << 16) - 1 // largest possible UDP datagram
)

// Infinite memory growth quickly oom-kills processes on small devices
// Allow fine tuning on such systems.
var PreallocatedBuffersPerPool uint32 = 0          // Disable and allow for infinite memory growth
