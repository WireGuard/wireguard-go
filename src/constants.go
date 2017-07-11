package main

import (
	"time"
)

/* Specification constants */

const (
	RekeyAfterMessages      = (1 << 64) - (1 << 16) - 1
	RejectAfterMessages     = (1 << 64) - (1 << 4) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5
	RejectAfterTime         = time.Second * 180
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 120
	MaxHandshakeAttemptTime = time.Second * 90
)

const (
	RekeyAfterTimeReceiving = RekeyAfterTime - KeepaliveTimeout - RekeyTimeout
)

/* Implementation specific constants */

const (
	QueueOutboundSize      = 1024
	QueueInboundSize       = 1024
	QueueHandshakeSize     = 1024
	QueueHandshakeBusySize = QueueHandshakeSize / 8
	MinMessageSize         = MessageTransportSize // keep-alive
	MaxMessageSize         = 4096                 // TODO: make depend on the MTU?
)
