// +build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

/* Fit within memory limits for iOS's Network Extension API, which has stricter requirements */

const (
	QueueOutboundSize          = 1024
	QueueInboundSize           = 1024
	QueueHandshakeSize         = 1024
	MaxSegmentSize             = 1700
	PreallocatedBuffersPerPool = 1024
)
