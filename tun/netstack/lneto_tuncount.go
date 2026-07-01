//go:build debugheaplog

package netstack

import "fmt"

// TUN-boundary packet counters, compiled in only under the debugheaplog tag
// (the start.sh -debug flag). They disambiguate a one-way data path: egress is
// what the stack hands to WireGuard (stack -> WG), ingress is what WireGuard
// feeds back into the stack (WG -> stack). A stuck SYN-SENT with egress>0 and
// ingress==0 means replies never reach the TUN; egress==0 means the stack is
// not draining its tx. Single counters are fine: js/wasm is single-threaded.
var (
	egressPkts, egressBytes   int
	ingressPkts, ingressBytes int
)

// countEgress records one non-empty packet pulled from the stack toward WireGuard.
func countEgress(n int) {
	egressPkts++
	egressBytes += n
	fmt.Printf("[TUNCOUNT] egress  pkts=%d bytes=%d last=%d\n", egressPkts, egressBytes, n)
}

// countIngress records one IP packet handed from WireGuard into the stack.
func countIngress(n int) {
	ingressPkts++
	ingressBytes += n
	fmt.Printf("[TUNCOUNT] ingress pkts=%d bytes=%d last=%d\n", ingressPkts, ingressBytes, n)
}
