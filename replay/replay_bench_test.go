/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package replay

import "testing"

// filter is the shared surface for Filter vs FilterV2 benches.
type filter interface {
	ValidateCounter(counter, limit uint64) bool
}

func runBoth(b *testing.B, fn func(b *testing.B, f filter)) {
	b.Run("v1", func(b *testing.B) {
		var f Filter
		fn(b, &f)
	})
	b.Run("v2", func(b *testing.B) {
		f := NewFilterV2()
		fn(b, &f)
	})
}

func BenchmarkSequential(b *testing.B) {
	runBoth(b, benchSequential)
}

func benchSequential(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ValidateCounter(uint64(i), RejectAfterMessages)
	}
}

func BenchmarkOutOfOrder(b *testing.B) {
	runBoth(b, benchOutOfOrder)
}

func benchOutOfOrder(b *testing.B, f filter) {
	for i := uint64(0); i < windowSize; i++ {
		f.ValidateCounter(i, RejectAfterMessages)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := windowSize - 1 - uint64(i)%windowSize
		f.ValidateCounter(c, RejectAfterMessages)
	}
}

func BenchmarkDuplicates(b *testing.B) {
	runBoth(b, benchDuplicates)
}

func benchDuplicates(b *testing.B, f filter) {
	f.ValidateCounter(42, RejectAfterMessages)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ValidateCounter(42, RejectAfterMessages)
	}
}

func BenchmarkJumpAhead(b *testing.B) {
	runBoth(b, benchJumpAhead)
}

func benchJumpAhead(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ValidateCounter(uint64(i)*uint64(windowSize+1), RejectAfterMessages)
	}
}

func BenchmarkMixed(b *testing.B) {
	runBoth(b, benchMixed)
}

func benchMixed(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := uint64(i)
		switch i % 16 {
		case 0:
			if n > 0 {
				f.ValidateCounter(n-1, RejectAfterMessages)
			}
		case 1:
			if n > 64 {
				f.ValidateCounter(n-uint64(i%64), RejectAfterMessages)
			}
		default:
			f.ValidateCounter(n, RejectAfterMessages)
		}
	}
}

// BenchmarkBehindWindow: advance the window, then repeatedly poke counters
// that fall outside it (pure reject-behind path).
func BenchmarkBehindWindow(b *testing.B) {
	runBoth(b, benchBehindWindow)
}

func benchBehindWindow(b *testing.B, f filter) {
	f.ValidateCounter(windowSize+1000, RejectAfterMessages)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ValidateCounter(uint64(i%100), RejectAfterMessages)
	}
}

// BenchmarkHalfBoundary: sequential traffic that keeps crossing v2 half clears
// (every ringBlocks blocks ≈ 8192 counters).
func BenchmarkHalfBoundary(b *testing.B) {
	runBoth(b, benchHalfBoundary)
}

func benchHalfBoundary(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	// Stride by one full half each op so almost every call triggers a clear.
	stride := uint64(ringBlocks) * blockBits
	for i := 0; i < b.N; i++ {
		f.ValidateCounter(uint64(i)*stride, RejectAfterMessages)
	}
}

// BenchmarkSmallGaps: mostly forward progress with occasional lost packets
// (small holes, then continue). Common mild loss pattern.
func BenchmarkSmallGaps(b *testing.B) {
	runBoth(b, benchSmallGaps)
}

func benchSmallGaps(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	var c uint64
	for i := 0; i < b.N; i++ {
		if i%32 == 0 {
			c += 3 // skip a few
		} else {
			c++
		}
		f.ValidateCounter(c, RejectAfterMessages)
	}
}

// BenchmarkFillHoles: advance with gaps, then fill unseen counters inside the
// window (accept path for late-but-new packets).
func BenchmarkFillHoles(b *testing.B) {
	runBoth(b, benchFillHoles)
}

func benchFillHoles(b *testing.B, f filter) {
	// Pre-seed: even counters only up through the window.
	for i := uint64(0); i < windowSize; i += 2 {
		f.ValidateCounter(i, RejectAfterMessages)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Odd counters: first pass accepts, later passes reject as replays.
		c := 1 + 2*(uint64(i)%(windowSize/2))
		f.ValidateCounter(c, RejectAfterMessages)
	}
}

// BenchmarkBurstReorder: sequential with periodic bursts of late packets
// from the last ~256 counters (closer to real jitter).
func BenchmarkBurstReorder(b *testing.B) {
	runBoth(b, benchBurstReorder)
}

func benchBurstReorder(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	var last uint64
	for i := 0; i < b.N; i++ {
		if i%20 == 19 && last > 256 {
			// Burst of 4 late packets.
			base := last - 256
			f.ValidateCounter(base+uint64(i%200), RejectAfterMessages)
			f.ValidateCounter(base+uint64(i%200)+1, RejectAfterMessages)
			f.ValidateCounter(base+uint64(i%200)+2, RejectAfterMessages)
			f.ValidateCounter(base+uint64(i%200)+3, RejectAfterMessages)
		} else {
			last++
			f.ValidateCounter(last, RejectAfterMessages)
		}
	}
}

// BenchmarkMediumJump: jumps of a few blocks (loss bursts) — clears some
// slots in v1, usually not a full half clear in v2.
func BenchmarkMediumJump(b *testing.B) {
	runBoth(b, benchMediumJump)
}

func benchMediumJump(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	stride := uint64(16 * blockBits) // 16 blocks ≈ 1024 counters
	for i := 0; i < b.N; i++ {
		f.ValidateCounter(uint64(i)*stride, RejectAfterMessages)
	}
}

// BenchmarkWindowEdge: keep advancing by 1, and each step also touch the
// oldest counter still inside the window.
func BenchmarkWindowEdge(b *testing.B) {
	runBoth(b, benchWindowEdge)
}

func benchWindowEdge(b *testing.B, f filter) {
	// Get past the first window so oldest-in-window is well defined.
	for i := uint64(0); i <= windowSize+10; i++ {
		f.ValidateCounter(i, RejectAfterMessages)
	}
	b.ReportAllocs()
	b.ResetTimer()
	last := uint64(windowSize + 10)
	for i := 0; i < b.N; i++ {
		last++
		f.ValidateCounter(last, RejectAfterMessages)
		f.ValidateCounter(last-windowSize, RejectAfterMessages) // oldest edge
	}
}

// BenchmarkRealistic approximates a WireGuard receive counter stream under
// ordinary Internet/Wi‑Fi conditions:
//
//	~95%   in-order +1 (dominant when the path is healthy)
//	~3%    small loss gap (+2..+8) — single/short drops, never delivered
//	~1.5%  late/dup of a recent counter (jitter / link-layer repeat)
//	~0.4%  medium burst gap (~64..~512) — Wi‑Fi/buffer drop bursts
//	~0.1%  large jump (> window) — long outage, then traffic resumes
//
// Frequencies are deterministic (i-mod) so runs stay comparable.
func BenchmarkRealistic(b *testing.B) {
	runBoth(b, benchRealistic)
}

func benchRealistic(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	var c uint64
	for i := 0; i < b.N; i++ {
		switch {
		case i%1000 == 999:
			// ~0.1%: large jump past the replay window.
			c += uint64(windowSize) + 1 + uint64(i%256)
			f.ValidateCounter(c, RejectAfterMessages)
		case i%250 == 249:
			// ~0.4%: medium burst loss.
			c += 64 + uint64(i%449)
			f.ValidateCounter(c, RejectAfterMessages)
		case i%67 == 66:
			// ~1.5%: late or duplicate from the recent past.
			if c > 64 {
				f.ValidateCounter(c-1-uint64(i%32), RejectAfterMessages)
			} else {
				f.ValidateCounter(c, RejectAfterMessages)
			}
		case i%33 == 32:
			// ~3%: small gap from a few lost packets.
			c += 2 + uint64(i%7)
			f.ValidateCounter(c, RejectAfterMessages)
		default:
			// ~95%: normal in-order delivery.
			c++
			f.ValidateCounter(c, RejectAfterMessages)
		}
	}
}

// BenchmarkSparseInWindow: large gaps that still land inside the sliding
// window (no clear of a full half, but sparse bit sets).
func BenchmarkSparseInWindow(b *testing.B) {
	runBoth(b, benchSparseInWindow)
}

func benchSparseInWindow(b *testing.B, f filter) {
	b.ReportAllocs()
	b.ResetTimer()
	var last uint64
	for i := 0; i < b.N; i++ {
		last += 97 // prime stride, stays << windowSize growth rate relative to ops
		if last > windowSize && i%8 == 0 {
			// Occasional look-back inside the window.
			f.ValidateCounter(last-uint64(windowSize/3), RejectAfterMessages)
		} else {
			f.ValidateCounter(last, RejectAfterMessages)
		}
	}
}
