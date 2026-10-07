package replay

import (
	"math/rand"
	"testing"
)

// diffPair runs the same counter sequence against Filter and FilterV2.
type diffPair struct {
	t *testing.T
	a Filter
	b FilterV2
}

func newDiffPair(t *testing.T) *diffPair {
	t.Helper()
	return &diffPair{t: t, b: NewFilterV2()}
}

func (d *diffPair) check(n uint64) {
	d.t.Helper()
	g1 := d.a.ValidateCounter(n, RejectAfterMessages)
	g2 := d.b.ValidateCounter(n, RejectAfterMessages)
	if g1 != g2 {
		d.t.Fatalf("mismatch at counter %d: v1=%v v2=%v", n, g1, g2)
	}
}

func (d *diffPair) checkLimit(n, limit uint64) {
	d.t.Helper()
	g1 := d.a.ValidateCounter(n, limit)
	g2 := d.b.ValidateCounter(n, limit)
	if g1 != g2 {
		d.t.Fatalf("mismatch at counter %d limit %d: v1=%v v2=%v", n, limit, g1, g2)
	}
}

// Temporary differential test: FilterV2 must match Filter decisions.
func TestV2MatchesV1(t *testing.T) {
	d := newDiffPair(t)

	// Sequential 0..8192 (crosses the half boundary at block 128).
	for i := uint64(0); i <= 8192; i++ {
		d.check(i)
	}
	// Replay a recent counter, still inside windowSize.
	d.check(8000)
}

func TestV2JumpAhead(t *testing.T) {
	d := newDiffPair(t)

	d.check(0)
	// Big jump: several ring-widths ahead.
	d.check(100000)
	// Same counter again must be rejected by both.
	d.check(100000)
	// Next counter accepted by both.
	d.check(100001)
}

// TestV2MultiHalfJump: a jump spanning >= 2 halves must not leave stale bits
// in the half that wasn't cleared.
func TestV2MultiHalfJump(t *testing.T) {
	d := newDiffPair(t)

	// Fill blocks 0..255 (both halves of the 2x ring).
	for i := uint64(0); i <= 16383; i++ {
		d.check(i)
	}
	// Jump to block 520 (half A), skipping all of blocks 256..519 —
	// including the whole of half B's range.
	d.check(33280)
	// Never-seen counter at block 400 (maps into half B, within window).
	// Half B still holds phase-1 bits for block 144 -> same slot, so a
	// stale-bit bug shows up as a false reject here.
	d.check(25600)
}

func TestV2BehindWindow(t *testing.T) {
	d := newDiffPair(t)

	d.check(windowSize + 100)
	// Far behind the window: both must reject.
	d.check(0)
	d.check(99)
	// Oldest still inside the window.
	d.check(100)
	d.check(100) // replay
}

func TestV2WindowBoundary(t *testing.T) {
	d := newDiffPair(t)

	last := uint64(50000)
	d.check(last)

	// Exactly windowSize behind last is still accepted (if unseen).
	d.check(last - windowSize)
	// One further back is outside the window.
	d.check(last - windowSize - 1)
}

func TestV2ReorderWithHoles(t *testing.T) {
	d := newDiffPair(t)

	// Arrive with gaps, then fill holes (classic reordering).
	for _, n := range []uint64{0, 5, 10, 3, 1, 2, 4, 9, 6, 7, 8} {
		d.check(n)
	}
	// Everything in 0..10 already seen.
	for n := uint64(0); n <= 10; n++ {
		d.check(n)
	}
}

func TestV2CrossTwoHalfBoundaries(t *testing.T) {
	d := newDiffPair(t)

	// Cross block 128 and block 256, replaying near each boundary.
	for i := uint64(0); i <= 20000; i++ {
		d.check(i)
	}
	d.check(19900)
	d.check(10000) // still in window relative to 20000
	d.check(9000)  // may be in or out depending on windowSize; both must agree
}

func TestV2SmallJumpWithinHalf(t *testing.T) {
	d := newDiffPair(t)

	for i := uint64(0); i < 1000; i++ {
		d.check(i)
	}
	// Jump forward, but stay inside the same clear-half.
	d.check(3000)
	d.check(2500) // inside window, unseen gap -> accept
	d.check(999)  // already seen
	d.check(3000) // replay
}

func TestV2JumpExactlyOneHalf(t *testing.T) {
	d := newDiffPair(t)

	// Land exactly on the next clearPoint half boundary.
	for i := uint64(0); i < uint64(ringBlocks)*blockBits; i++ {
		d.check(i)
	}
	// Next half starts at block ringBlocks.
	d.check(uint64(ringBlocks) * blockBits)
	// Replay something from the previous half that is still in-window.
	d.check(uint64(ringBlocks)*blockBits - 100)
}

func TestV2RepeatedJumps(t *testing.T) {
	d := newDiffPair(t)

	var c uint64
	for jump := 0; jump < 8; jump++ {
		c += uint64(windowSize) + uint64(jump*97) + 1
		d.check(c)
		d.check(c)     // duplicate
		d.check(c + 1) // successor
		c++
		// Late packet still inside the window.
		if c > 50 {
			d.check(c - 50)
		}
	}
}

func TestV2LimitRejection(t *testing.T) {
	d := newDiffPair(t)

	limit := uint64(1000)
	for i := uint64(0); i < 10; i++ {
		d.checkLimit(i, limit)
	}
	d.checkLimit(limit-1, limit)
	d.checkLimit(limit, limit)   // == limit -> reject
	d.checkLimit(limit+1, limit) // > limit -> reject
	d.checkLimit(999, limit)     // replay of accepted
}

func TestV2RejectAfterMessages(t *testing.T) {
	d := newDiffPair(t)

	d.check(RejectAfterMessages - 1)
	d.check(RejectAfterMessages)
	d.check(RejectAfterMessages + 1)
	d.check(RejectAfterMessages - 2)
	d.check(RejectAfterMessages - 1) // replay
}

func TestV2Descending(t *testing.T) {
	d := newDiffPair(t)

	// Reverse arrival order within a fresh window.
	for i := uint64(windowSize); i > 0; i-- {
		d.check(i)
	}
	d.check(0)
	d.check(windowSize + 1)
	d.check(0) // now behind or replay — both must agree
}

func TestV2SparseWithinWindow(t *testing.T) {
	d := newDiffPair(t)

	d.check(0)
	d.check(windowSize)
	// Skip around inside the window.
	for _, n := range []uint64{2, 100, 1000, 4000, 7000, 50, 999, 4000} {
		d.check(n)
	}
}

func TestV2Randomized(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	d := newDiffPair(t)

	var last uint64
	for i := 0; i < 5000; i++ {
		var n uint64
		switch rng.Intn(5) {
		case 0:
			// Sequential-ish advance.
			last++
			n = last
		case 1:
			// Small reorder behind last.
			if last > 64 {
				n = last - uint64(rng.Intn(64))
			} else {
				n = last
			}
		case 2:
			// Duplicate.
			n = last
		case 3:
			// Medium jump ahead.
			last += uint64(rng.Intn(int(windowSize/2))) + 1
			n = last
		default:
			// Occasional large jump.
			last += uint64(windowSize) + uint64(rng.Intn(10000)) + 1
			n = last
		}
		d.check(n)
	}
}
