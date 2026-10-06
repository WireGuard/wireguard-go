//go:build !netstackdebug

package netstack

func debugIPPacket(egress bool, pkt []byte) {}
