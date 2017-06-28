package main

import (
	"net"
)

const (
	IPv4version    = 4
	IPv4offsetSrc  = 12
	IPv4offsetDst  = IPv4offsetSrc + net.IPv4len
	IPv4headerSize = 20
)

const (
	IPv6version   = 6
	IPv6offsetSrc = 8
	IPv6offsetDst = IPv6offsetSrc + net.IPv6len
)
