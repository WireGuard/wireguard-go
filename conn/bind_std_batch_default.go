//go:build !linux && !android && !darwin

package conn

import "net"

const stdNetBindBatches = false

func (s *StdNetBind) setupBatch(v4conn, v6conn *net.UDPConn) {}
