//go:build wglneto

package netstack

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// CreateNetTUN builds the lneto-backed netstack TUN device. This is the
// implementation selected when building with -tags wglneto.
func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error) {
	return CreateNetTUNLneto(localAddresses, dnsServers, mtu)
}
