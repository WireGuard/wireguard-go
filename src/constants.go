package main

import (
	"time"
)

/* Specification constants */

const (
	RekeyAfterMessages     = (1 << 64) - (1 << 16) - 1
	RejectAfterMessages    = (1 << 64) - (1 << 4) - 1
	RekeyAfterTime         = time.Second * 120
	RekeyAttemptTime       = time.Second * 90
	RekeyTimeout           = time.Second * 5
	RejectAfterTime        = time.Second * 180
	KeepaliveTimeout       = time.Second * 10
	CookieRefreshTime      = time.Second * 120
	HandshakeInitationRate = time.Second / 20
	PaddingMultiple        = 16
)

const (
	RekeyAfterTimeReceiving = RekeyAfterTime - KeepaliveTimeout - RekeyTimeout
	NewHandshakeTime        = KeepaliveTimeout + RekeyTimeout // upon failure to acknowledge transport message
)

/* Implementation specific constants */

const (
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	MinMessageSize     = MessageTransportSize // size of keep-alive
	MaxMessageSize     = ((1 << 16) - 1) + MessageTransportHeaderSize
	MaxPeers           = 1 << 16
)

const (
	UnderLoadQueueSize = QueueHandshakeSize / 8
	UnderLoadAfterTime = time.Second // how long does the device remain under load after detected
)
