package device

import (
	"testing"
)

var sinkS string

func BenchmarkPeerString(b *testing.B) {
	k := [32]byte{0: 0x4e, 1: 0xb3, 2: 0x2f, 29: 0x16, 30: 0x5d, 31: 0x7d} // TrMv…WXX0
	p := &Peer{handshake: Handshake{remoteStatic: k}}
	s := p.String()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s = p.String()
	}
	sinkS = s
}
