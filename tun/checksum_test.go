package tun

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	"golang.org/x/sys/unix"
)

func checksumRef(b []byte, initial uint16) uint16 {
	ac := uint64(initial)

	for len(b) >= 2 {
		ac += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		ac += uint64(b[0]) << 8
	}

	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(ac)
}

func pseudoHeaderChecksumRefNoFold(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint16 {
	sum := checksumRef(srcAddr, 0)
	sum = checksumRef(dstAddr, sum)
	sum = checksumRef([]byte{0, protocol}, sum)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	return checksumRef(tmp, sum)
}

func TestChecksum(t *testing.T) {
	for length := 0; length <= 9001; length++ {
		buf := make([]byte, length)
		rng := rand.New(rand.NewSource(1))
		rng.Read(buf)
		csum := checksum(buf, 0x1234)
		csumRef := checksumRef(buf, 0x1234)
		if csum != csumRef {
			t.Error("Expected checksum", csumRef, "got", csum)
		}
	}
}

func TestPseudoHeaderChecksum(t *testing.T) {
	for _, addrLen := range []int{4, 16} {
		for length := 0; length <= 9001; length++ {
			srcAddr := make([]byte, addrLen)
			dstAddr := make([]byte, addrLen)
			buf := make([]byte, length)
			rng := rand.New(rand.NewSource(1))
			rng.Read(srcAddr)
			rng.Read(dstAddr)
			rng.Read(buf)
			phSum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(length))
			csum := checksum(buf, phSum)
			phSumRef := pseudoHeaderChecksumRefNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(length))
			csumRef := checksumRef(buf, phSumRef)
			if csum != csumRef {
				t.Error("Expected checksumRef", csumRef, "got", csum)
			}
		}
	}
}

func BenchmarkChecksum(b *testing.B) {
	lengths := []int{
		64,
		128,
		256,
		512,
		1024,
		1500,
		2048,
		4096,
		8192,
		9000,
		9001,
	}

	for _, length := range lengths {
		b.Run(fmt.Sprintf("%d", length), func(b *testing.B) {
			buf := make([]byte, length)
			rng := rand.New(rand.NewSource(1))
			rng.Read(buf)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				checksum(buf, 0)
			}
		})
	}
}
