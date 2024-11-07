package conn

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type ReceiverCreator interface {
	CreateIPv4ReceiverFn(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool, msgPool *sync.Pool) ReceiveFunc
}
