package conn

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

// for ice bind receiver
type WebRtcBinder interface {
	IPv4Bind(pool *sync.Pool, pkt *ipv4.PacketConn, udpconn *net.UDPConn) ReceiveFunc
}

func NewWebRtcBind(binder WebRtcBinder) *StdNetBind {
	std, _ := NewStdNetBind().(*StdNetBind)
	std.webRTCBinder = binder
	return std
}
