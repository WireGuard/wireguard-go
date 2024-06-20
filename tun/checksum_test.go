package tun

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
)

func checksumRef(b []byte, initial uint64) uint16 {
	ac := initial

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

func checksumOldNoFold(b []byte, initial uint64) uint64 {
	ac := initial

	for len(b) >= 128 {
		ac += uint64(binary.BigEndian.Uint32(b[:4]))
		ac += uint64(binary.BigEndian.Uint32(b[4:8]))
		ac += uint64(binary.BigEndian.Uint32(b[8:12]))
		ac += uint64(binary.BigEndian.Uint32(b[12:16]))
		ac += uint64(binary.BigEndian.Uint32(b[16:20]))
		ac += uint64(binary.BigEndian.Uint32(b[20:24]))
		ac += uint64(binary.BigEndian.Uint32(b[24:28]))
		ac += uint64(binary.BigEndian.Uint32(b[28:32]))
		ac += uint64(binary.BigEndian.Uint32(b[32:36]))
		ac += uint64(binary.BigEndian.Uint32(b[36:40]))
		ac += uint64(binary.BigEndian.Uint32(b[40:44]))
		ac += uint64(binary.BigEndian.Uint32(b[44:48]))
		ac += uint64(binary.BigEndian.Uint32(b[48:52]))
		ac += uint64(binary.BigEndian.Uint32(b[52:56]))
		ac += uint64(binary.BigEndian.Uint32(b[56:60]))
		ac += uint64(binary.BigEndian.Uint32(b[60:64]))
		ac += uint64(binary.BigEndian.Uint32(b[64:68]))
		ac += uint64(binary.BigEndian.Uint32(b[68:72]))
		ac += uint64(binary.BigEndian.Uint32(b[72:76]))
		ac += uint64(binary.BigEndian.Uint32(b[76:80]))
		ac += uint64(binary.BigEndian.Uint32(b[80:84]))
		ac += uint64(binary.BigEndian.Uint32(b[84:88]))
		ac += uint64(binary.BigEndian.Uint32(b[88:92]))
		ac += uint64(binary.BigEndian.Uint32(b[92:96]))
		ac += uint64(binary.BigEndian.Uint32(b[96:100]))
		ac += uint64(binary.BigEndian.Uint32(b[100:104]))
		ac += uint64(binary.BigEndian.Uint32(b[104:108]))
		ac += uint64(binary.BigEndian.Uint32(b[108:112]))
		ac += uint64(binary.BigEndian.Uint32(b[112:116]))
		ac += uint64(binary.BigEndian.Uint32(b[116:120]))
		ac += uint64(binary.BigEndian.Uint32(b[120:124]))
		ac += uint64(binary.BigEndian.Uint32(b[124:128]))
		b = b[128:]
	}
	if len(b) >= 64 {
		ac += uint64(binary.BigEndian.Uint32(b[:4]))
		ac += uint64(binary.BigEndian.Uint32(b[4:8]))
		ac += uint64(binary.BigEndian.Uint32(b[8:12]))
		ac += uint64(binary.BigEndian.Uint32(b[12:16]))
		ac += uint64(binary.BigEndian.Uint32(b[16:20]))
		ac += uint64(binary.BigEndian.Uint32(b[20:24]))
		ac += uint64(binary.BigEndian.Uint32(b[24:28]))
		ac += uint64(binary.BigEndian.Uint32(b[28:32]))
		ac += uint64(binary.BigEndian.Uint32(b[32:36]))
		ac += uint64(binary.BigEndian.Uint32(b[36:40]))
		ac += uint64(binary.BigEndian.Uint32(b[40:44]))
		ac += uint64(binary.BigEndian.Uint32(b[44:48]))
		ac += uint64(binary.BigEndian.Uint32(b[48:52]))
		ac += uint64(binary.BigEndian.Uint32(b[52:56]))
		ac += uint64(binary.BigEndian.Uint32(b[56:60]))
		ac += uint64(binary.BigEndian.Uint32(b[60:64]))
		b = b[64:]
	}
	if len(b) >= 32 {
		ac += uint64(binary.BigEndian.Uint32(b[:4]))
		ac += uint64(binary.BigEndian.Uint32(b[4:8]))
		ac += uint64(binary.BigEndian.Uint32(b[8:12]))
		ac += uint64(binary.BigEndian.Uint32(b[12:16]))
		ac += uint64(binary.BigEndian.Uint32(b[16:20]))
		ac += uint64(binary.BigEndian.Uint32(b[20:24]))
		ac += uint64(binary.BigEndian.Uint32(b[24:28]))
		ac += uint64(binary.BigEndian.Uint32(b[28:32]))
		b = b[32:]
	}
	if len(b) >= 16 {
		ac += uint64(binary.BigEndian.Uint32(b[:4]))
		ac += uint64(binary.BigEndian.Uint32(b[4:8]))
		ac += uint64(binary.BigEndian.Uint32(b[8:12]))
		ac += uint64(binary.BigEndian.Uint32(b[12:16]))
		b = b[16:]
	}
	if len(b) >= 8 {
		ac += uint64(binary.BigEndian.Uint32(b[:4]))
		ac += uint64(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
	}
	if len(b) >= 4 {
		ac += uint64(binary.BigEndian.Uint32(b))
		b = b[4:]
	}
	if len(b) >= 2 {
		ac += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		ac += uint64(b[0]) << 8
	}

	return ac
}

func checksumOld(b []byte, initial uint64) uint16 {
	ac := checksumOldNoFold(b, initial)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	return uint16(ac)
}

var lengths = [...]int{
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

func TestChecksum(t *testing.T) {
	for _, length := range lengths {
		buf := make([]byte, length)
		rng := rand.New(rand.NewSource(1))
		rng.Read(buf)
		csum := checksum(buf, 0)
		csumRef := checksumRef(buf, 0)
		csumOld := checksumOld(buf, 0)
		if csum != csumRef {
			t.Error("Expected checksum", csumRef, "got", csum)
		} else if csum != csumOld {
			t.Error("Expected checksumOld", csumOld, "got", csum)
		}
	}
}

func BenchmarkChecksum(b *testing.B) {
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

func BenchmarkChecksumOld(b *testing.B) {
	for _, length := range lengths {
		b.Run(fmt.Sprintf("%d", length), func(b *testing.B) {
			buf := make([]byte, length)
			rng := rand.New(rand.NewSource(1))
			rng.Read(buf)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				checksumOld(buf, 0)
			}
		})
	}
}
