package fec

import (
	"fmt"
	"errors"
	"github.com/xssnick/raptorq"
)

// For RaptorQ, the Decode process is more stateful.
// The FECProtector interface's Decode method is a bit awkward for fountain codes.
// We'll make it work by assuming receivedPackets for RaptorQ are just a collection of symbols
// that the decoder will try to use. A more ideal API for RaptorQ would be AddSymbol().
// For now, this is a simplified wrapper.

type rqProtector struct {
	rq         raptorq.RaptorQ
	numSourceSymbols  uint // K: number of source symbols (source packets)
	symbolSize uint16 // T: size of each symbol in bytes
	// RaptorQ doesn't have a fixed number of "parity" shards in the same way RS does.
	// It can generate a stream of repair symbols.
}

// NewRaptorQProtector creates a new RaptorQ FEC scheme.
// numSourcePackets: The number of original data packets (K).
// packetSize: The size of each packet/symbol (T). All source packets should ideally be this size.
//             If smaller, they should be padded. If larger, they need to be chunked.
//             For this wrapper, we assume source packets are pre-chunked to fit symbolSize.
func NewRaptorQProtector(numSourcePackets int, symbolSize uint16) (FECProtector, error) {
	if numSourcePackets <= 0 {
		return nil, errors.New("number of source packets must be positive for RaptorQ")
	}
	if symbolSize == 0 {
		return nil, errors.New("symbol size must be positive for RaptorQ")
	}
	return &rqProtector{
		rq:        raptorq.NewRaptorQ(symbolSize), // symbolSize is T
		numSourceSymbols: uint(numSourcePackets),
		symbolSize: symbolSize,
	}, nil
}

func (r *rqProtector) Algorithm() FECAlgorithmType {
	return RaptorQ
}

func (r *rqProtector) NumDataShards() int {
	return int(r.numSourceSymbols)
}

func (r *rqProtector) NumParityShards() int {
	// Variable for RaptorQ; depends on how many repair symbols are generated.
	// This interface field is less meaningful for RaptorQ. Return 0 or a typical overhead.
	return 0 // Or perhaps some default overhead factor, but it's not fixed like RS.
}

func (r *rqProtector) TotalShards() int {
	// Also variable.
	return int(r.numSourceSymbols) // Represents the minimum needed for decode.
}


// Encode for RaptorQ: takes K source packets, pads them if necessary,
// then returns K source symbols + P repair symbols.
// For this wrapper, let's say it returns K source symbols + K repair symbols (configurable later).
func (r *rqProtector) Encode(sourcePackets []Packet) ([]Packet, error) {
	if len(sourcePackets) != int(r.numSourceSymbols) {
		return nil, fmt.Errorf("RaptorQ Encode: expected %d source packets, got %d", r.numSourceSymbols, len(sourcePackets))
	}

	// Concatenate all source packets into one large buffer, padding each to symbolSize.
	// This is a simplification. RaptorQ libraries often operate on a single contiguous block of data.
	// xssnick/raptorq expects a single []byte payload for the encoder.

	payload := make([]byte, 0, int(r.numSourceSymbols)*int(r.symbolSize))
	for i, p := range sourcePackets {
		if p == nil {
			return nil, fmt.Errorf("RaptorQ Encode: source packet at index %d is nil", i)
		}
		if len(p) > int(r.symbolSize) {
			return nil, fmt.Errorf("RaptorQ Encode: source packet %d length %d exceeds symbol size %d", i, len(p), r.symbolSize)
		}
		paddedP := make([]byte, r.symbolSize)
		copy(paddedP, p)
		payload = append(payload, paddedP...)
	}

	enc, err := r.rq.CreateEncoder(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create RaptorQ encoder: %w", err)
	}

	numRepairSymbolsToGenerate := r.numSourceSymbols // Generate K repair symbols for now (K data, K repair)
	outputSymbols := make([]Packet, 0, int(r.numSourceSymbols) + int(numRepairSymbolsToGenerate))

	for i := uint32(0); i < uint32(r.numSourceSymbols); i++ {
		outputSymbols = append(outputSymbols, Packet(enc.GenSymbol(i)))
	}
	for i := uint32(0); i < uint32(numRepairSymbolsToGenerate); i++ {
		// Symbol IDs for repair symbols typically start after source symbols,
		// but GenSymbol handles the internal logic for LT/repair symbols.
		// The ESI (Encoding Symbol ID) for repair symbols can be > K.
		// xssnick/raptorq GenSymbol(i) generates:
		//   - source symbol if i < K
		//   - repair symbol if i >= K
		outputSymbols = append(outputSymbols, Packet(enc.GenSymbol(uint32(r.numSourceSymbols) + i)))
	}
	return outputSymbols, nil
}

// Decode for RaptorQ: receivedPackets are symbols. Their original ESI (Encoding Symbol ID) is crucial.
// The current FECProtector.Decode interface is not ideal as it doesn't pass symbol IDs.
// This implementation will ASSUME receivedPackets contains symbols WITH THEIR IDs SOMEHOW.
// This is a major simplification and likely needs rework for real use.
// For now, let's assume receivedPackets[i] is symbol with ID i. This is often NOT the case.
// A better approach would be:
// type RaptorQSymbol struct { ID uint32; Data []byte }
// func (r *rqProtector) AddSymbol(symbol RaptorQSymbol) (bool, error)
// func (r *rqProtector) AttemptDecode() ([]Packet, error)
//
// Sticking to the interface for now means we make a big assumption:
// receivedPackets contains *at least* K symbols, and their position in the slice *might* imply ID
// or they are a mix and we just feed them all.
func (r *rqProtector) Decode(receivedSymbols []Packet) ([]Packet, error) {
	payloadLen := uint64(r.numSourceSymbols) * uint64(r.symbolSize)
	dec, err := r.rq.CreateDecoder(payloadLen)
	if err != nil {
		return nil, fmt.Errorf("failed to create RaptorQ decoder: %w", err)
	}

	if len(receivedSymbols) < int(r.numSourceSymbols) {
		// This check is weak because RaptorQ can decode with K symbols even if they are not the first K.
		// return nil, fmt.Errorf("RaptorQ Decode: not enough symbols (%d) to reconstruct, need at least %d", len(receivedSymbols), r.numSourceSymbols)
	}

	addedCount := 0
	for i, sData := range receivedSymbols {
		if sData == nil { // Skip nil symbols (erasures)
			continue
		}
		// BIG ASSUMPTION: index i is the symbol ID. This needs to be fixed by changing interface or using a convention.
		// For xssnick/raptorq, AddSymbol takes (symbolID uint32, data []byte).
		// We don't have symbol IDs here properly. Let's assume the first K are source, rest are repair.
		// This is a placeholder until the interface can be adapted or a clear convention is set.
		// For now, we'll just add them with their index as ID.
		symbolID := uint32(i) // THIS IS LIKELY WRONG FOR REAL SCENARIOS

		canTry, err := dec.AddSymbol(symbolID, sData)
		if err != nil {
			// Some errors from AddSymbol are expected if symbol is duplicate or invalid, log them?
			// For now, continue trying to add others.
			// fmt.Printf("RaptorQ Decode: error adding symbol %d: %v
", symbolID, err)
			continue
		}
		addedCount++
		if canTry {
			success, resultData, decodeErr := dec.Decode()
			if decodeErr != nil {
				return nil, fmt.Errorf("RaptorQ decoding attempt failed: %w", decodeErr)
			}
			if success {
				// resultData is a single byte slice. We need to split it back into K packets.
				reconstructedPackets := make([]Packet, r.numSourceSymbols)
				for j := 0; j < int(r.numSourceSymbols); j++ {
					start := j * int(r.symbolSize)
					end := start + int(r.symbolSize)
					if end > len(resultData) {
						 return nil, fmt.Errorf("RaptorQ Decode: reconstructed data too short to extract all source packets. Expected len %d, got %d", payloadLen, len(resultData))
					}
					reconstructedPackets[j] = Packet(resultData[start:end])
				}
				return reconstructedPackets, nil
			}
		}
	}
	return nil, fmt.Errorf("RaptorQ Decode: failed to decode with %d provided symbols (attempted to add %d)", len(receivedSymbols), addedCount)
}
