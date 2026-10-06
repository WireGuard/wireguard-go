//go:build netstackdebug

package netstack

import (
	"os"
	"sync"
	"time"

	"github.com/soypat/lneto/x/xnet"
)

var (
	_pcap     xnet.CapturePrinter
	_pcapOnce sync.Once
)

func debugIPPacket(egress bool, pkt []byte) {
	_pcapOnce.Do(func() {
		_pcap.Configure(os.Stdout, xnet.CapturePrinterConfig{
			NamespaceWidth: 3,
			TimePrecision:  4,
			Now:            time.Now,
		})
	})
	if egress {
		_pcap.PrintIP("OUT", pkt)
	} else {
		_pcap.PrintIP("IN ", pkt)
	}
}
