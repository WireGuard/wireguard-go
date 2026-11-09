//go:build linux || android

package conn

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const stdNetBindBatches = true

func (s *StdNetBind) setupBatch(v4conn, v6conn *net.UDPConn) {
	if v4conn != nil {
		s.batch4 = ipv4.NewPacketConn(v4conn)
	}
	if v6conn != nil {
		s.batch6 = ipv6.NewPacketConn(v6conn)
	}
}
