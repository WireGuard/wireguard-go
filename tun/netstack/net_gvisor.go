//go:build !wglneto

package netstack

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// CreateNetTUN builds the default gvisor-backed netstack TUN device. Build with
// -tags wglneto to select the lneto backend instead (see CreateNetTUNLneto).
func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error) {
	return CreateNetTUNGvisor(localAddresses, dnsServers, mtu)
}
