package main

import (
	"time"
)

const (
	RekeyAfterMessages      = (1 << 64) - (1 << 16) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5 // TODO: Exponential backoff
	RejectAfterTime         = time.Second * 180
	RejectAfterMessages     = (1 << 64) - (1 << 4) - 1
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 2
	MaxHandshakeAttemptTime = time.Second * 90
)

const (
	QueueOutboundSize      = 1024
	QueueInboundSize       = 1024
	QueueHandshakeSize     = 1024
	QueueHandshakeBusySize = QueueHandshakeSize / 8
	MinMessageSize         = MessageTransportSize // keep-alive
	MaxMessageSize         = 4096
)
