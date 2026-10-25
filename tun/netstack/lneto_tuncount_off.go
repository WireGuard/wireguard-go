//go:build !debugheaplog

package netstack

// No-op TUN-boundary counters for non-debug builds; calls are inlined away.
func countEgress(int)  {}
func countIngress(int) {}
