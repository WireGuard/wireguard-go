package tun

import (
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"sort"
	"syscall"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
	gvisorChecksum "gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type archChecksumDetails struct {
	name      string
	available bool
	f         func([]byte, uint16) uint16
}

func deterministicRandomBytes(seed int64, length int) []byte {
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, length)
	n, err := rng.Read(buf)
	if err != nil {
		panic(err)
	}
	if n != length {
		panic("incomplete random buffer")
	}
	return buf
}

func getPageAlignedRandomBytes(seed int64, length int) []byte {
	alignment := syscall.Getpagesize()
	buf := deterministicRandomBytes(seed, length+(alignment-1))
	bufPtr := uintptr(unsafe.Pointer(&buf[0]))
	alignedBufPtr := (bufPtr + uintptr(alignment-1)) & ^uintptr(alignment-1)
	alignedStart := int(alignedBufPtr - bufPtr)
	return buf[alignedStart:]
}

func TestChecksum(t *testing.T) {
	alignedBuf := getPageAlignedRandomBytes(10, 8192)
	allOnes := make([]byte, 65535)
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	allFE := make([]byte, 65535)
	for i := range allFE {
		allFE[i] = 0xfe
	}

	tests := []struct {
		name    string
		data    []byte
		initial uint16
		want    uint16
	}{
		{
			name:    "empty",
			data:    []byte{},
			initial: 0,
			want:    0,
		},
		{
			name:    "max initial",
			data:    []byte{},
			initial: math.MaxUint16,
			want:    0xffff,
		},
		{
			name:    "odd length",
			data:    []byte{0x01, 0x02, 0x01},
			initial: 0,
			want:    0x0202,
		},
		{
			name:    "tiny",
			data:    []byte{0x01, 0x02, 0x01, 0x02, 0x01, 0x02},
			initial: 0,
			want:    0x0306,
		},
		{
			name:    "initial",
			data:    []byte{0x01, 0x02, 0x01, 0x02, 0x01, 0x02},
			initial: 0x1000,
			want:    0x1306,
		},
		// cleanup0 through cleanup15 is 1024 (handled by large SIMD loops) +
		// 32 (handled by small SIMD loops) + n, where n ranges from 0 to 15
		// to cover all of the leftover byte sizes that are possible after small
		// SIMD loops that handle 16 bytes.
		{
			name:    "cleanup0",
			data:    deterministicRandomBytes(1, 1056),
			initial: 0,
			want:    0x11ec,
		},
		{
			name:    "cleanup1",
			data:    deterministicRandomBytes(1, 1057),
			initial: 0,
			want:    0xc5ec,
		},
		{
			name:    "cleanup2",
			data:    deterministicRandomBytes(1, 1058),
			initial: 0,
			want:    0xc6ad,
		},
		{
			name:    "cleanup3",
			data:    deterministicRandomBytes(1, 1059),
			initial: 0,
			want:    0x86ae,
		},
		{
			name:    "cleanup4",
			data:    deterministicRandomBytes(1, 1060),
			initial: 0,
			want:    0x878e,
		},
		{
			name:    "cleanup5",
			data:    deterministicRandomBytes(1, 1061),
			initial: 0,
			want:    0xdb8e,
		},
		{
			name:    "cleanup6",
			data:    deterministicRandomBytes(1, 1062),
			initial: 0,
			want:    0xdbd5,
		},
		{
			name:    "cleanup7",
			data:    deterministicRandomBytes(1, 1063),
			initial: 0,
			want:    0xcfd6,
		},
		{
			name:    "cleanup8",
			data:    deterministicRandomBytes(1, 1064),
			initial: 0,
			want:    0xd090,
		},
		{
			name:    "cleanup9",
			data:    deterministicRandomBytes(1, 1065),
			initial: 0,
			want:    0x0791,
		},
		{
			name:    "cleanup10",
			data:    deterministicRandomBytes(1, 1066),
			initial: 0,
			want:    0x079f,
		},
		{
			name:    "cleanup11",
			data:    deterministicRandomBytes(1, 1067),
			initial: 0,
			want:    0xba9f,
		},
		{
			name:    "cleanup12",
			data:    deterministicRandomBytes(1, 1068),
			initial: 0,
			want:    0xbb0c,
		},
		{
			name:    "cleanup13",
			data:    deterministicRandomBytes(1, 1069),
			initial: 0,
			want:    0x770d,
		},
		{
			name:    "cleanup14",
			data:    deterministicRandomBytes(1, 1070),
			initial: 0,
			want:    0x780a,
		},
		{
			name:    "cleanup15",
			data:    deterministicRandomBytes(1, 1071),
			initial: 0,
			want:    0x640b,
		},
		// small1 through small15 covers small sizes that are not large enough
		// to do overlapped reads.
		{
			name:    "small1",
			data:    deterministicRandomBytes(2, 1),
			initial: 0x1122,
			want:    0x4022,
		},
		{
			name:    "small2",
			data:    deterministicRandomBytes(2, 2),
			initial: 0x1122,
			want:    0x40a4,
		},
		{
			name:    "small3",
			data:    deterministicRandomBytes(2, 3),
			initial: 0x1122,
			want:    0xc2a4,
		},
		{
			name:    "small4",
			data:    deterministicRandomBytes(2, 4),
			initial: 0x1122,
			want:    0xc36f,
		},
		{
			name:    "small5",
			data:    deterministicRandomBytes(2, 5),
			initial: 0x1122,
			want:    0xa570,
		},
		{
			name:    "small6",
			data:    deterministicRandomBytes(2, 6),
			initial: 0x1122,
			want:    0xa669,
		},
		{
			name:    "small7",
			data:    deterministicRandomBytes(2, 7),
			initial: 0x1122,
			want:    0x0f6a,
		},
		{
			name:    "small8",
			data:    deterministicRandomBytes(2, 8),
			initial: 0x1122,
			want:    0x0fd9,
		},
		{
			name:    "small9",
			data:    deterministicRandomBytes(2, 9),
			initial: 0x1122,
			want:    0x40d9,
		},
		{
			name:    "small10",
			data:    deterministicRandomBytes(2, 10),
			initial: 0x1122,
			want:    0x411d,
		},
		{
			name:    "small11",
			data:    deterministicRandomBytes(2, 11),
			initial: 0x1122,
			want:    0x011e,
		},
		{
			name:    "small12",
			data:    deterministicRandomBytes(2, 12),
			initial: 0x1122,
			want:    0x01c8,
		},
		{
			name:    "small13",
			data:    deterministicRandomBytes(2, 13),
			initial: 0x1122,
			want:    0x4dc8,
		},
		{
			name:    "small14",
			data:    deterministicRandomBytes(2, 14),
			initial: 0x1122,
			want:    0x4eb5,
		},
		{
			name:    "small15",
			data:    deterministicRandomBytes(2, 15),
			initial: 0x1122,
			want:    0xa4b5,
		},
		// other small-ish sizes
		{
			name:    "small16",
			data:    deterministicRandomBytes(1, 16),
			initial: 0,
			want:    0x02fa,
		},
		{
			name:    "small32",
			data:    deterministicRandomBytes(1, 32),
			initial: 0,
			want:    0x03ee,
		},
		{
			name:    "small64",
			data:    deterministicRandomBytes(1, 64),
			initial: 0,
			want:    0x3f85,
		},
		{
			name:    "medium",
			data:    deterministicRandomBytes(1, 1400),
			initial: 0,
			want:    0xbea5,
		},
		{
			name:    "big",
			data:    deterministicRandomBytes(2, 65000),
			initial: 0,
			want:    0x3ba7,
		},
		{
			name:    "big-initial",
			data:    deterministicRandomBytes(2, 65000),
			initial: 0x1234,
			want:    0x4ddb,
		},
		{
			// big-small-loop is intended to exercise a few iterations of a big
			// initial loop of 128 bytes or larger + a smaller loop of 16 bytes
			// + some leftover
			name:    "big-small-loop",
			data:    deterministicRandomBytes(3, 1094),
			initial: 0x9999,
			want:    0xe65b,
		},
		{
			name:    "page-aligned",
			data:    alignedBuf[:4096],
			initial: 0,
			want:    0x963b,
		},
		{
			name:    "32-aligned",
			data:    alignedBuf[32:4128],
			initial: 0,
			want:    0x30c4,
		},
		{
			name:    "16-aligned",
			data:    alignedBuf[16:4112],
			initial: 0,
			want:    0xaeff,
		},
		{
			name:    "8-aligned",
			data:    alignedBuf[8:4104],
			initial: 0,
			want:    0x6c3b,
		},
		{
			name:    "4-aligned",
			data:    alignedBuf[4:4100],
			initial: 0,
			want:    0x2e4a,
		},
		{
			name:    "2-aligned",
			data:    alignedBuf[2:4098],
			initial: 0,
			want:    0xc702,
		},
		{
			name:    "unaligned",
			data:    alignedBuf[1:4097],
			initial: 0,
			want:    0x3bc7,
		},
		{
			name:    "unalignedAndOdd",
			data:    alignedBuf[1:4096],
			initial: 0,
			want:    0x3b13,
		},
		{
			name:    "fe1282",
			data:    allFE[:1282],
			initial: 0,
			want:    0x7c7c,
		},
		{
			name:    "fe",
			data:    allFE,
			initial: 0,
			want:    0x7e81,
		},
		{
			name:    "maximum",
			data:    allOnes,
			initial: 0,
			want:    0xff00,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, fd := range archChecksumFuncs {
				t.Run(fd.name, func(t *testing.T) {
					if !fd.available {
						t.Skip("can not run on this system")
					}
					if got := fd.f(tt.data, tt.initial); got != tt.want {
						t.Errorf("%s checksum = %04x, want %04x", fd.name, got, tt.want)
					}
				})
			}
			t.Run("reference", func(t *testing.T) {
				if got := gvisorChecksum.Checksum(tt.data, tt.initial); got != tt.want {
					t.Errorf("reference checksum = %04x, want %04x", got, tt.want)
				}
			})
		})
	}
}

func TestPseudoHeaderChecksumNoFold(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint8
		srcAddr  []byte
		dstAddr  []byte
		totalLen uint16
		want     uint16
	}{
		{
			name:     "ipv4",
			protocol: syscall.IPPROTO_TCP,
			srcAddr:  netip.MustParseAddr("192.168.1.1").AsSlice(),
			dstAddr:  netip.MustParseAddr("192.168.1.2").AsSlice(),
			totalLen: 1492,
			want:     0x892e,
		},
		{
			name:     "ipv6",
			protocol: syscall.IPPROTO_TCP,
			srcAddr:  netip.MustParseAddr("2001:db8:3333:4444:5555:6666:7777:8888").AsSlice(),
			dstAddr:  netip.MustParseAddr("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff").AsSlice(),
			totalLen: 1492,
			want:     0x947f,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("pseudoHeaderChecksum32", func(t *testing.T) {
				got := pseudoHeaderChecksum32(tt.protocol, tt.srcAddr, tt.dstAddr, tt.totalLen)
				if got != tt.want {
					t.Errorf("got %04x, want %04x", got, tt.want)
				}
			})
			t.Run("pseudoHeaderChecksum64", func(t *testing.T) {
				got := pseudoHeaderChecksum64(tt.protocol, tt.srcAddr, tt.dstAddr, tt.totalLen)
				if got != tt.want {
					t.Errorf("got %04x, want %04x", got, tt.want)
				}
			})
			t.Run("reference", func(t *testing.T) {
				got := header.PseudoHeaderChecksum(
					tcpip.TransportProtocolNumber(tt.protocol),
					tcpip.Address(tt.srcAddr),
					tcpip.Address(tt.dstAddr),
					tt.totalLen)
				if got != tt.want {
					t.Errorf("got %04x, want %04x", got, tt.want)
				}
			})
		})
	}
}

func FuzzChecksum(f *testing.F) {
	buf := getPageAlignedRandomBytes(1234, 65536)

	f.Add([]byte{}, uint16(0))
	f.Add([]byte{}, uint16(0x1234))
	f.Add([]byte{}, uint16(0))
	f.Add(buf[:15], uint16(0x1234))
	f.Add(buf[:256], uint16(0x1234))
	f.Add(buf[:1280], uint16(0x1234))
	f.Add(buf[:1288], uint16(0x1234))
	f.Add(buf[1:1050], uint16(0x1234))

	f.Fuzz(func(t *testing.T, data []byte, initial uint16) {
		want := gvisorChecksum.Checksum(data, initial)

		for _, fd := range archChecksumFuncs {
			t.Run(fd.name, func(t *testing.T) {
				if !fd.available {
					t.Skip("can not run on this system")
				}
				if got := fd.f(data, initial); got != want {
					t.Errorf("%s checksum = %04x, want %04x", fd.name, got, want)
				}
			})
		}
	})
}

var result uint16

func BenchmarkChecksum(b *testing.B) {
	offsets := []int{ // offsets from page alignment
		0,
		1,
		2,
		4,
		8,
		16,
	}
	lengths := []int{
		0,
		7,
		15,
		16,
		31,
		64,
		90,
		95,
		128,
		256,
		512,
		1024,
		1240,
		1500,
		2048,
		4096,
		8192,
		9000,
		9001,
		16384,
		65536,
	}
	if !sort.IntsAreSorted(offsets) {
		b.Fatal("offsets are not sorted")
	}
	largestLength := lengths[len(lengths)-1]
	if !sort.IntsAreSorted(lengths) {
		b.Fatal("lengths are not sorted")
	}
	largestOffset := lengths[len(offsets)-1]
	alignedBuf := getPageAlignedRandomBytes(1, largestOffset+largestLength)
	var r uint16
	for _, offset := range offsets {
		name := fmt.Sprintf("%vAligned", offset)
		if offset == 0 {
			name = "pageAligned"
		}
		offsetBuf := alignedBuf[offset:]
		b.Run(name, func(b *testing.B) {
			for _, length := range lengths {
				b.Run(fmt.Sprintf("%d", length), func(b *testing.B) {
					for _, fd := range archChecksumFuncs {
						b.Run(fd.name, func(b *testing.B) {
							if !fd.available {
								b.Skip("can not run on this system")
							}
							b.SetBytes(int64(length))
							for i := 0; i < b.N; i++ {
								r += fd.f(offsetBuf[:length], 0)
							}
						})
					}
				})
			}
		})
	}
	result = r
}

func BenchmarkPseudoHeaderChecksum(b *testing.B) {
	tests := []struct {
		name     string
		protocol uint8
		srcAddr  []byte
		dstAddr  []byte
		totalLen uint16
		want     uint16
	}{
		{
			name:     "ipv4",
			protocol: syscall.IPPROTO_TCP,
			srcAddr:  []byte{192, 168, 1, 1},
			dstAddr:  []byte{192, 168, 1, 2},
			totalLen: 1492,
			want:     0x892e,
		},
		{
			name:     "ipv6",
			protocol: syscall.IPPROTO_TCP,
			srcAddr:  netip.MustParseAddr("2001:db8:3333:4444:5555:6666:7777:8888").AsSlice(),
			dstAddr:  netip.MustParseAddr("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff").AsSlice(),
			totalLen: 1492,
			want:     0x892e,
		},
	}
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.Run("pseudoHeaderChecksum32", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					result += pseudoHeaderChecksum32(tt.protocol, tt.srcAddr, tt.dstAddr, tt.totalLen)
				}
			})
			b.Run("pseudoHeaderChecksum64", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					result += pseudoHeaderChecksum64(tt.protocol, tt.srcAddr, tt.dstAddr, tt.totalLen)
				}
			})
		})
	}
}
