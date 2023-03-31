//go:build ignore

//go:generate go run generate_amd64.go -out checksum_generated_amd64.s -stubs checksum_generated_amd64.go

package main

import (
	"fmt"
	"math"
	"math/bits"

	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

const checksumSignature = "func(b []byte, initial uint16) uint16"

func loadParams() (accum, buf, n reg.GPVirtual) {
	accum, buf, n = GP64(), GP64(), GP64()
	Load(Param("initial"), accum)
	XCHGB(accum.As8H(), accum.As8L())
	Load(Param("b").Base(), buf)
	Load(Param("b").Len(), n)
	return
}

type simdStrategy int

const (
	sse2 = iota
	avx2
)

const tinyBufferSize = 31 // A buffer is tiny if it has at most 31 bytes.

func generateSIMDChecksum(name, doc string, minSIMDSize, chains int, strategy simdStrategy) {
	TEXT(name, NOSPLIT|NOFRAME, checksumSignature)
	Pragma("noescape")
	Doc(doc)

	accum64, buf, n := loadParams()

	handleOddLength(n, buf, accum64)
	// no chance of overflow because accum64 was initialized by a uint16 and
	// handleOddLength adds at most a uint8
	handleTinyBuffers(n, buf, accum64, operand.LabelRef("foldAndReturn"), operand.LabelRef("bufferIsNotTiny"))
	Label("bufferIsNotTiny")

	const simdReadSize = 16

	if minSIMDSize > tinyBufferSize {
		Comment("skip all SIMD for small buffers")
		if minSIMDSize <= math.MaxUint8 {
			CMPQ(n, operand.U8(minSIMDSize))
		} else {
			CMPQ(n, operand.U32(minSIMDSize))
		}
		JGE(operand.LabelRef("startSIMD"))

		handleRemaining(n, buf, accum64, minSIMDSize-1)
		JMP(operand.LabelRef("foldAndReturn"))
	}

	Label("startSIMD")

	// chains is the number of accumulators to use. This improves speed via
	// reduced data dependency. We combine the accumulators once when the big
	// loop is complete.
	simdAccumulate := make([]reg.VecVirtual, chains)
	for i := range simdAccumulate {
		switch strategy {
		case sse2:
			simdAccumulate[i] = XMM()
			PXOR(simdAccumulate[i], simdAccumulate[i])
		case avx2:
			simdAccumulate[i] = YMM()
			VPXOR(simdAccumulate[i], simdAccumulate[i], simdAccumulate[i])
		}
	}
	var zero reg.VecVirtual
	if strategy == sse2 {
		zero = XMM()
		PXOR(zero, zero)
	}

	// Number of loads per big loop
	const unroll = 16
	// Number of bytes
	loopSize := uint64(simdReadSize * unroll)
	if bits.Len64(loopSize) != bits.Len64(loopSize-1)+1 {
		panic("loopSize is not a power of 2")
	}
	loopCount := GP64()

	MOVQ(n, loopCount)
	Comment("Update number of bytes remaining after the loop completes")
	ANDQ(operand.Imm(loopSize-1), n)
	Comment(fmt.Sprintf("Number of %d byte iterations", loopSize))
	SHRQ(operand.Imm(uint64(bits.Len64(loopSize-1))), loopCount)
	JZ(operand.LabelRef("smallLoop"))
	Label("bigLoop")
	for i := 0; i < unroll; i++ {
		chain := i % chains
		switch strategy {
		case sse2:
			sse2AccumulateStep(i*simdReadSize, buf, zero, simdAccumulate[chain], simdAccumulate[(chain+chains/2)%chains])
		case avx2:
			avx2AccumulateStep(i*simdReadSize, buf, simdAccumulate[chain])
		}
	}
	ADDQ(operand.U32(loopSize), buf)
	DECQ(loopCount)
	JNZ(operand.LabelRef("bigLoop"))

	Label("bigCleanup")

	CMPQ(n, operand.Imm(uint64(simdReadSize)))
	JLT(operand.LabelRef("doneSmallLoop"))

	Commentf("now read a single %d byte unit of data at a time", simdReadSize)
	Label("smallLoop")

	switch strategy {
	case sse2:
		sse2AccumulateStep(0, buf, zero, simdAccumulate[0], simdAccumulate[1])
	case avx2:
		avx2AccumulateStep(0, buf, simdAccumulate[0])
	}
	ADDQ(operand.Imm(uint64(simdReadSize)), buf)
	SUBQ(operand.Imm(uint64(simdReadSize)), n)
	CMPQ(n, operand.Imm(uint64(simdReadSize)))
	JGE(operand.LabelRef("smallLoop"))

	Label("doneSmallLoop")
	CMPQ(n, operand.Imm(0))
	JE(operand.LabelRef("doneSIMD"))

	Commentf("There are between 1 and %d bytes remaining. Perform an overlapped read.", simdReadSize-1)

	maskDataPtr := GP64()
	LEAQ(operand.NewDataAddr(operand.NewStaticSymbol("xmmLoadMasks"), 0), maskDataPtr)
	dataAddr := operand.Mem{Index: n, Scale: 1, Base: buf, Disp: -simdReadSize}
	// scale 8 is only correct here because n is guaranteed to be even and we
	// do not generate masks for odd lengths
	maskAddr := operand.Mem{Base: maskDataPtr, Index: n, Scale: 8, Disp: -16}
	remainder := XMM()

	switch strategy {
	case sse2:
		MOVOU(dataAddr, remainder)
		PAND(maskAddr, remainder)
		low := XMM()
		MOVOA(remainder, low)
		PUNPCKHWL(zero, remainder)
		PUNPCKLWL(zero, low)
		PADDD(remainder, simdAccumulate[0])
		PADDD(low, simdAccumulate[1])
	case avx2:
		// Note: this is very similar to the sse2 path but MOVOU has a massive
		// performance hit if used here, presumably due to switching between SSE
		// and AVX2 modes.
		VMOVDQU(dataAddr, remainder)
		VPAND(maskAddr, remainder, remainder)

		temp := YMM()
		VPMOVZXWD(remainder, temp)
		VPADDD(temp, simdAccumulate[0], simdAccumulate[0])
	}

	Label("doneSIMD")

	Comment("Multi-chain loop is done, combine the accumulators")
	for i := range simdAccumulate {
		if i == 0 {
			continue
		}
		switch strategy {
		case sse2:
			PADDD(simdAccumulate[i], simdAccumulate[0])
		case avx2:
			VPADDD(simdAccumulate[i], simdAccumulate[0], simdAccumulate[0])
		}
	}

	if strategy == avx2 {
		Comment("extract the YMM into a pair of XMM and sum them")
		tmp := YMM()
		VEXTRACTI128(operand.Imm(1), simdAccumulate[0], tmp.AsX())

		xAccumulate := XMM()
		VPADDD(simdAccumulate[0].AsX(), tmp.AsX(), xAccumulate)
		simdAccumulate = []reg.VecVirtual{xAccumulate}
	}

	Comment("extract the XMM into GP64")
	low, high := GP64(), GP64()
	switch strategy {
	case sse2:
		MOVQ(simdAccumulate[0], low)
		PSRLDQ(operand.Imm(8), simdAccumulate[0])
		MOVQ(simdAccumulate[0], high)
	case avx2:
		VPEXTRQ(operand.Imm(0), simdAccumulate[0], low)
		VPEXTRQ(operand.Imm(1), simdAccumulate[0], high)

		Comment("no more AVX code, clear upper registers to avoid SSE slowdowns")
		VZEROUPPER()
	}
	ADDQ(low, accum64)
	ADCQ(high, accum64)
	Label("foldAndReturn")
	foldWithCF(accum64, strategy == avx2)
	XCHGB(accum64.As8H(), accum64.As8L())
	Store(accum64.As16(), ReturnIndex(0))
	RET()
}

// handleOddLength generates instructions to incorporate the last byte into
// accum64 if the length is odd. CF may be set if accum64 overflows; be sure to
// handle that if overflow is possible.
func handleOddLength(n, buf, accum64 reg.GPVirtual) {
	Comment("handle odd length buffers; they are difficult to handle in general")
	TESTQ(operand.U32(1), n)
	JZ(operand.LabelRef("lengthIsEven"))

	tmp := GP64()
	MOVBQZX(operand.Mem{Base: buf, Index: n, Scale: 1, Disp: -1}, tmp)
	DECQ(n)
	ADDQ(tmp, accum64)

	Label("lengthIsEven")
}

func sse2AccumulateStep(offset int, buf reg.GPVirtual, zero, accumulate1, accumulate2 reg.VecVirtual) {
	high, low := XMM(), XMM()
	MOVOU(operand.Mem{Disp: offset, Base: buf}, high)
	MOVOA(high, low)
	PUNPCKHWL(zero, high)
	PUNPCKLWL(zero, low)
	PADDD(high, accumulate1)
	PADDD(low, accumulate2)
}

func avx2AccumulateStep(offset int, buf reg.GPVirtual, accumulate reg.VecVirtual) {
	tmp := YMM()
	VPMOVZXWD(operand.Mem{Disp: offset, Base: buf}, tmp)
	VPADDD(tmp, accumulate, accumulate)
}

func generateAMD64Checksum(name, doc string) {
	TEXT(name, NOSPLIT|NOFRAME, checksumSignature)
	Pragma("noescape")
	Doc(doc)

	accum64, buf, n := loadParams()

	handleOddLength(n, buf, accum64)
	// no chance of overflow because accum64 was initialized by a uint16 and
	// handleOddLength adds at most a uint8
	handleTinyBuffers(n, buf, accum64, operand.LabelRef("foldAndReturn"), operand.LabelRef("bufferIsNotTiny"))
	Label("bufferIsNotTiny")

	const (
		// numChains is the number of accumulators and carry counters to use.
		// This improves speed via reduced data dependency. We combine the
		// accumulators and carry counters once when the loop is complete.
		numChains = 4
		unroll    = 32         // The number of 64-bit reads to perform per iteration of the loop.
		loopSize  = 8 * unroll // The number of bytes read per iteration of the loop.
	)
	if bits.Len(loopSize) != bits.Len(loopSize-1)+1 {
		panic("loopSize is not a power of 2")
	}
	loopCount := GP64()

	Comment(fmt.Sprintf("Number of %d byte iterations into loop counter", loopSize))
	MOVQ(n, loopCount)
	Comment("Update number of bytes remaining after the loop completes")
	ANDQ(operand.Imm(loopSize-1), n)
	SHRQ(operand.Imm(uint64(bits.Len(loopSize-1))), loopCount)
	JZ(operand.LabelRef("startCleanup"))
	CLC()

	chains := make([]struct {
		accum   reg.GPVirtual
		carries reg.GPVirtual
	}, numChains)
	for i := range chains {
		if i == 0 {
			chains[i].accum = accum64
		} else {
			chains[i].accum = GP64()
			XORQ(chains[i].accum, chains[i].accum)
		}
		chains[i].carries = GP64()
		XORQ(chains[i].carries, chains[i].carries)
	}

	Label("bigLoop")

	var curChain int
	for i := 0; i < unroll; i++ {
		// It is significantly faster to use a ADCX/ADOX pair instead of plain
		// ADC, which results in two dependency chains, however those require
		// ADX support, which was added after AVX2. If AVX2 is available, that's
		// even better than ADCX/ADOX.
		//
		// However, multiple dependency chains using multiple accumulators and
		// occasionally storing CF into temporary counters seems to work almost
		// as well.
		addr := operand.Mem{Disp: i * 8, Base: buf}

		if i%4 == 0 {
			if i > 0 {
				ADCQ(operand.Imm(0), chains[curChain].carries)
				curChain = (curChain + 1) % len(chains)
			}
			ADDQ(addr, chains[curChain].accum)
		} else {
			ADCQ(addr, chains[curChain].accum)
		}
	}
	ADCQ(operand.Imm(0), chains[curChain].carries)
	ADDQ(operand.U32(loopSize), buf)
	SUBQ(operand.Imm(1), loopCount)
	JNZ(operand.LabelRef("bigLoop"))
	for i := range chains {
		if i == 0 {
			ADDQ(chains[i].carries, accum64)
			continue
		}
		ADCQ(chains[i].accum, accum64)
		ADCQ(chains[i].carries, accum64)
	}

	accumulateCF(accum64)

	Label("startCleanup")
	handleRemaining(n, buf, accum64, loopSize-1)
	Label("foldAndReturn")
	foldWithCF(accum64, false)

	XCHGB(accum64.As8H(), accum64.As8L())
	Store(accum64.As16(), ReturnIndex(0))
	RET()
}

// handleTinyBuffers computes checksums if the buffer length (the n parameter)
// is less than 32. After computing the checksum, a jump to returnLabel will
// be executed. Otherwise, if the buffer length is at least 32, nothing will be
// modified; a jump to continueLabel will be executed instead.
//
// When jumping to returnLabel, CF may be set and must be accommodated e.g.
// using foldWithCF or accumulateCF.
//
// Anecdotally, this appears to be faster than attempting to coordinate an
// overlapped read (which would also require special handling for buffers
// smaller than 8).
func handleTinyBuffers(n, buf, accum reg.GPVirtual, returnLabel, continueLabel operand.LabelRef) {
	Comment("handle tiny buffers (<=31 bytes) specially")
	CMPQ(n, operand.Imm(tinyBufferSize))
	JGT(continueLabel)

	tmp2, tmp4, tmp8 := GP64(), GP64(), GP64()
	XORQ(tmp2, tmp2)
	XORQ(tmp4, tmp4)
	XORQ(tmp8, tmp8)

	Comment("shift twice to start because length is guaranteed to be even",
		"n = n >> 2; CF = originalN & 2")
	SHRQ(operand.Imm(2), n)
	JNC(operand.LabelRef("handleTiny4"))
	Comment("tmp2 = binary.LittleEndian.Uint16(buf[:2]); buf = buf[2:]")
	MOVWQZX(operand.Mem{Base: buf}, tmp2)
	ADDQ(operand.Imm(2), buf)

	Label("handleTiny4")
	Comment("n = n >> 1; CF = originalN & 4")
	SHRQ(operand.Imm(1), n)
	JNC(operand.LabelRef("handleTiny8"))
	Comment("tmp4 = binary.LittleEndian.Uint32(buf[:4]); buf = buf[4:]")
	MOVLQZX(operand.Mem{Base: buf}, tmp4)
	ADDQ(operand.Imm(4), buf)

	Label("handleTiny8")
	Comment("n = n >> 1; CF = originalN & 8")
	SHRQ(operand.Imm(1), n)
	JNC(operand.LabelRef("handleTiny16"))
	Comment("tmp8 = binary.LittleEndian.Uint64(buf[:8]); buf = buf[8:]")
	MOVQ(operand.Mem{Base: buf}, tmp8)
	ADDQ(operand.Imm(8), buf)

	Label("handleTiny16")
	Comment("n = n >> 1; CF = originalN & 16",
		"n == 0 now, otherwise we would have branched after comparing with tinyBufferSize")
	SHRQ(operand.Imm(1), n)
	JNC(operand.LabelRef("handleTinyFinish"))
	ADDQ(operand.Mem{Base: buf}, accum)
	ADCQ(operand.Mem{Base: buf, Disp: 8}, accum)

	Label("handleTinyFinish")
	Comment("CF should be included from the previous add, so we use ADCQ.",
		"If we arrived via the JNC above, then CF=0 due to the branch condition,",
		"so ADCQ will still produce the correct result.")
	ADCQ(tmp2, accum)
	ADCQ(tmp4, accum)
	ADCQ(tmp8, accum)

	JMP(returnLabel)
}

// handleRemaining generates a series of conditional unrolled additions,
// starting with 8 bytes long and doubling each time until the length reaches
// max. This is the reverse order of what may be intuitive, but makes the branch
// conditions convenient to compute: perform one right shift each time and test
// against CF.
//
// When done, CF may be set and must be accommodated e.g., using foldWithCF or
// accumulateCF.
//
// If n is not a multiple of 8, an extra 64 bit read at the end of the buffer
// will be performed, overlapping with data that will be read later. The
// duplicate data will be shifted off.
//
// The original buffer length must have been at least 8 bytes long, even if
// n < 8, otherwise this will access memory before the start of the buffer,
// which may be unsafe.
func handleRemaining(n, buf, accum64 reg.GPVirtual, max int) {
	Comment("Accumulate carries in this register. It is never expected to overflow.")
	carries := GP64()
	XORQ(carries, carries)

	Comment("We will perform an overlapped read for buffers with length not a multiple of 8.",
		"Overlapped in this context means some memory will be read twice, but a shift will",
		"eliminate the duplicated data. This extra read is performed at the end of the buffer to",
		"preserve any alignment that may exist for the start of the buffer.")
	leftover := reg.RCX
	MOVQ(n, leftover)
	SHRQ(operand.Imm(3), n)          // n is now the number of 64 bit reads remaining
	ANDQ(operand.Imm(0x7), leftover) // leftover is now the number of bytes to read from the end
	JZ(operand.LabelRef("handleRemaining8"))
	endBuf := GP64()
	// endBuf is the position near the end of the buffer that is just past the
	// last multiple of 8: (buf + len(buf)) & ^0x7
	LEAQ(operand.Mem{Base: buf, Index: n, Scale: 8}, endBuf)

	overlapRead := GP64()
	// equivalent to overlapRead = binary.LittleEndian.Uint64(buf[len(buf)-8:len(buf)])
	MOVQ(operand.Mem{Base: endBuf, Index: leftover, Scale: 1, Disp: -8}, overlapRead)

	Comment("Shift out the duplicated data: overlapRead = overlapRead >> (64 - leftoverBytes*8)")
	SHLQ(operand.Imm(3), leftover)  // leftover = leftover * 8
	NEGQ(leftover)                  // leftover = -leftover; this completes the (-leftoverBytes*8) part of the expression
	ADDQ(operand.Imm(64), leftover) // now we have (64 - leftoverBytes*8)
	SHRQ(reg.CL, overlapRead)       // shift right by (64 - leftoverBytes*8); CL is the low 8 bits of leftover (set to RCX above) and variable shift only accepts CL

	ADDQ(overlapRead, accum64)
	ADCQ(operand.Imm(0), carries)

	for curBytes := 8; curBytes <= max; curBytes *= 2 {
		Label(fmt.Sprintf("handleRemaining%d", curBytes))
		SHRQ(operand.Imm(1), n)
		if curBytes*2 <= max {
			JNC(operand.LabelRef(fmt.Sprintf("handleRemaining%d", curBytes*2)))
		} else {
			JNC(operand.LabelRef("handleRemainingComplete"))
		}

		numLoads := curBytes / 8
		for i := 0; i < numLoads; i++ {
			addr := operand.Mem{Base: buf, Disp: i * 8}
			// It is possible to add the multiple dependency chains trick here
			// that generateAMD64Checksum uses but anecdotally it does not
			// appear to outweigh the cost.
			if i == 0 {
				ADDQ(addr, accum64)
				continue
			}
			ADCQ(addr, accum64)
		}
		ADCQ(operand.Imm(0), carries)

		if curBytes > math.MaxUint8 {
			ADDQ(operand.U32(uint64(curBytes)), buf)
		} else {
			ADDQ(operand.U8(uint64(curBytes)), buf)
		}
		if curBytes*2 >= max {
			continue
		}
		JMP(operand.LabelRef(fmt.Sprintf("handleRemaining%d", curBytes*2)))
	}
	Label("handleRemainingComplete")
	ADDQ(carries, accum64)
}

func accumulateCF(accum64 reg.GPVirtual) {
	Comment("accumulate CF (twice, in case the first time overflows)")
	// accum64 += CF
	ADCQ(operand.Imm(0), accum64)
	// accum64 += CF again if the previous add overflowed. The previous add was
	// 0 or 1. If it overflowed, then accum64 == 0, so adding another 1 can
	// never overflow.
	ADCQ(operand.Imm(0), accum64)
}

// foldWithCF generates instructions to fold accum (a GP64) into a 16-bit value
// according to ones-complement arithmetic. BMI2 instructions will be used if
// allowBMI2 is true (requires fewer instructions).
func foldWithCF(accum reg.GPVirtual, allowBMI2 bool) {
	Comment("add CF and fold")

	// CF|accum max value starts as 0x1_ffff_ffff_ffff_ffff

	tmp := GP64()
	if allowBMI2 {
		// effectively, tmp = accum >> 32 (technically, this is a rotate)
		RORXQ(operand.Imm(32), accum, tmp)
		// accum as uint32 = uint32(accum) + uint32(tmp64) + CF; max value 0xffff_ffff + CF set
		ADCL(tmp.As32(), accum.As32())
		// effectively, tmp64 as uint32 = uint32(accum) >> 16 (also a rotate)
		RORXL(operand.Imm(16), accum.As32(), tmp.As32())
		// accum as uint16 = uint16(accum) + uint16(tmp) + CF; max value 0xffff + CF unset or 0xfffe + CF set
		ADCW(tmp.As16(), accum.As16())
	} else {
		// tmp = uint32(accum); max value 0xffff_ffff
		// MOVL clears the upper 32 bits of a GP64 so this is equivalent to the
		// non-existent MOVLQZX.
		MOVL(accum.As32(), tmp.As32())
		// tmp += CF; max value 0x1_0000_0000, CF unset
		ADCQ(operand.Imm(0), tmp)
		// accum = accum >> 32; max value 0xffff_ffff
		SHRQ(operand.Imm(32), accum)
		// accum = accum + tmp; max value 0x1_ffff_ffff + CF unset
		ADDQ(tmp, accum)
		// tmp = uint16(accum); max value 0xffff
		MOVWQZX(accum.As16(), tmp)
		// accum = accum >> 16; max value 0x1_ffff
		SHRQ(operand.Imm(16), accum)
		// accum = accum + tmp; max value 0x2_fffe + CF unset
		ADDQ(tmp, accum)
		// tmp as uint16 = uint16(accum); max value 0xffff
		MOVW(accum.As16(), tmp.As16())
		// accum = accum >> 16; max value 0x2
		SHRQ(operand.Imm(16), accum)
		// accum as uint16 = uint16(accum) + uint16(tmp); max value 0xffff + CF unset or 0x2 + CF set
		ADDW(tmp.As16(), accum.As16())
	}
	// accum as uint16 += CF; will not overflow: either CF was 0 or accum <= 0xfffe
	ADCW(operand.Imm(0), accum.As16())
}

func generateLoadMasks() {
	var offset int
	// xmmLoadMasks is a table of masks that can be used with PAND to zero all but the last N bytes in an XMM, N=2,4,6,8,10,12,14
	GLOBL("xmmLoadMasks", RODATA|NOPTR)

	for n := 2; n < 16; n += 2 {
		var pattern [16]byte
		for i := 0; i < len(pattern); i++ {
			if i < len(pattern)-n {
				pattern[i] = 0
				continue
			}
			pattern[i] = 0xff
		}
		DATA(offset, operand.String(pattern[:]))
		offset += len(pattern)
	}
}

func main() {
	generateLoadMasks()
	generateSIMDChecksum("checksumAVX2", "checksumAVX2 computes an IP checksum using amd64 v3 instructions (AVX2, BMI2)", 256, 4, avx2)
	generateSIMDChecksum("checksumSSE2", "checksumSSE2 computes an IP checksum using amd64 baseline instructions (SSE2)", 256, 4, sse2)
	generateAMD64Checksum("checksumAMD64", "checksumAMD64 computes an IP checksum using amd64 baseline instructions")
	Generate()
}
