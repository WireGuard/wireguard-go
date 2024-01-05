package conn

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type ReceiverCreator interface {
	CreateIPv4ReceiverFn(msgPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn) ReceiveFunc
}
