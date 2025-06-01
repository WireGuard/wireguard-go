/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"
)

/* Specification constants */

const (
	RekeyAfterMessages      = (1 << 60)
	RejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5
	MaxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / RekeyTimeout */
	RekeyTimeoutJitterMaxMs = 334
	RejectAfterTime         = time.Second * 180
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 120
	HandshakeInitationRate  = time.Second / 50
	PaddingMultiple         = 16
)

const (
	MinMessageSize = MessageKeepaliveSize                  // minimum size of transport message (keepalive)
	MaxMessageSize = MaxSegmentSize                        // maximum size of transport message
	MaxContentSize = MaxSegmentSize - MessageTransportSize // maximum size of transport message content
)

/* Implementation constants */

const (
	UnderLoadAfterTime = time.Second // how long does the device remain under load after detected
	MaxPeers           = 1 << 16     // maximum number of configured peers
)

// FEC Network Quality Thresholds
const (
	NoFECMaxLossRate     float64 = 0.01 // Up to 1% loss, no FEC
	XORFECMinLossRate    float64 = 0.01 // Minimum loss to consider XOR
	XORFECMaxLossRate    float64 = 0.05 // Up to 5% loss, use XOR
	RSFECMinLossRate     float64 = 0.05 // Minimum loss to consider RS
	RSFECMaxLossRate     float64 = 0.20 // Up to 20% loss, use RS
	RaptorFECMinLossRate float64 = 0.20 // Above 20% loss, use RaptorQ

	// Latency thresholds might also be used, e.g.
	// HighLatencyThresholdMillis int64 = 150
)

// FEC Packet Format Constants
const (
	FECMagicHeader             uint16 = 0xFEEC
	FECHeaderSize              int    = 11 // Bytes (Magic:2, Algo:1, Flags:1, GroupID:4, ShardIndex:1, OrigLen:2)

	// FECMaxDataShards is a practical limit on how many data shards we'll try to bundle.
	// This affects buffer sizes and GroupID generation.
	FECMaxDataShards           int = 16 // Example, can be tuned

	// FECMaxRepairShards is a practical limit on how many repair shards we might generate.
	FECMaxRepairShards         int = 8  // Example

	// FECMaxTotalShards = FECMaxDataShards + FECMaxRepairShards
	FECMaxTotalShards          int = FECMaxDataShards + FECMaxRepairShards

	// FECShardBufferTimeout is how long to wait for other shards in a group.
	FECShardBufferTimeout      time.Duration = 200 * time.Millisecond // Example
)

// FECFlags (bitmask)
const (
	FECFlagIsSourceShard        byte = 0x01 // If set, this shard is one of the original K data shards
	FECFlagIsLastSourceShard    byte = 0x02 // For RaptorQ primarily, indicates end of a source block for a group.
)
