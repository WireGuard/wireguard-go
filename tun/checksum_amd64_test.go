//go:build amd64

package tun

import (
	"golang.org/x/sys/cpu"
)

var archChecksumFuncs = []archChecksumDetails{
	{
		name:      "generic32",
		available: true,
		f:         checksumGeneric32,
	},
	{
		name:      "generic64",
		available: true,
		f:         checksumGeneric64,
	},
	{
		name:      "generic32Alternate",
		available: true,
		f:         checksumGeneric32Alternate,
	},
	{
		name:      "generic64Alternate",
		available: true,
		f:         checksumGeneric64Alternate,
	},
	{
		name:      "AMD64",
		available: true,
		f:         checksumAMD64,
	},
	{
		name:      "SSE2",
		available: cpu.X86.HasSSE2,
		f:         checksumSSE2,
	},
	{
		name:      "AVX2",
		available: cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2,
		f:         checksumAVX2,
	},
}
