package fec

import (
	"fmt"
	"github.com/klauspost/reedsolomon"
)

type rsProtector struct {
	enc         reedsolomon.Encoder
	dataShards  int
	parityShards int
}

func NewReedSolomonProtector(dataShards, parityShards int) (FECProtector, error) {
	enc, err := reedsolomon.New(dataShards, parityShards, reedsolomon.WithAutoGoroutines(1500)) // Assuming MTU around 1500
	if err != nil {
		return nil, fmt.Errorf("failed to create Reed-Solomon encoder: %w", err)
	}
	return &rsProtector{
		enc:         enc,
		dataShards:  dataShards,
		parityShards: parityShards,
	}, nil
}

func (rs *rsProtector) Algorithm() FECAlgorithmType {
	return ReedSolomon
}

func (rs *rsProtector) NumDataShards() int {
	return rs.dataShards
}

func (rs *rsProtector) NumParityShards() int {
	return rs.parityShards
}

func (rs *rsProtector) TotalShards() int {
	return rs.dataShards + rs.parityShards
}

func (rs *rsProtector) Encode(sourcePackets []Packet) ([]Packet, error) {
	if len(sourcePackets) != rs.dataShards {
		return nil, fmt.Errorf("RS Encode: expected %d source packets, got %d", rs.dataShards, len(sourcePackets))
	}

	shards := make([][]byte, rs.dataShards+rs.parityShards)
	maxLength := 0
	for i, p := range sourcePackets {
		if p == nil {
			return nil, fmt.Errorf("RS Encode: source packet at index %d is nil", i)
		}
		shards[i] = p
		if len(p) > maxLength {
			maxLength = len(p)
		}
	}

	// Ensure all data shards are padded to the same length before encoding
	// Parity shards will also be this length.
	for i := 0; i < rs.dataShards; i++ {
		if len(shards[i]) < maxLength {
			paddedShard := make([]byte, maxLength)
			copy(paddedShard, shards[i])
			shards[i] = paddedShard
		}
	}
	// Allocate parity shards
	for i := rs.dataShards; i < rs.dataShards+rs.parityShards; i++ {
		shards[i] = make([]byte, maxLength)
	}

	if err := rs.enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err)
	}

	outputPackets := make([]Packet, len(shards))
	for i, s := range shards {
		outputPackets[i] = Packet(s)
	}
	return outputPackets, nil
}

func (rs *rsProtector) Decode(receivedPackets []Packet) ([]Packet, error) {
	if len(receivedPackets) != rs.dataShards+rs.parityShards {
		return nil, fmt.Errorf("RS Decode: expected %d total packets, got %d", rs.dataShards+rs.parityShards, len(receivedPackets))
	}

	shards := make([][]byte, len(receivedPackets))
	nilCount := 0
	maxLength := 0
	for i, p := range receivedPackets {
		shards[i] = p // p can be nil
		if p == nil {
			nilCount++
		} else {
			if len(p) > maxLength {
				 maxLength = len(p)
			}
		}
	}

	if nilCount > rs.parityShards {
		return nil, fmt.Errorf("RS Decode: too many missing shards (%d), cannot reconstruct with %d parity shards", nilCount, rs.parityShards)
	}
	if nilCount == 0 { // No missing shards, just return the data shards
		// Before returning, ensure all data shards are consistently sized if they were padded.
		// However, the encoder already padded them, so they should be fine.
		// The contract is to return the K original data packets.
		return receivedPackets[:rs.dataShards], nil
	}

	// For reconstruction, all non-nil shards must be padded to the same length (max length of received)
	// if they aren't already. The encoder ensures this for its output.
	// If a shard is received and is shorter than others, it might be problematic for RS library.
	// The klauspost library expects shards to be of equal length for Encode,
	// and Reconstruct will reconstruct them to their original (equal) length.
	// We need to ensure any nil slots are represented, and non-nil are padded to consistent length
	// if they somehow became inconsistent (should not happen if sender is this code).
	for i, s := range shards {
		if s != nil && len(s) < maxLength {
			 paddedShard := make([]byte, maxLength)
			 copy(paddedShard, s)
			 shards[i] = paddedShard
		}
		// If s is nil, it's an erasure. klauspost library handles nil shards.
	}


	err := rs.enc.ReconstructData(shards) // Reconstructs only data shards in-place
	if err != nil {
		// Try Reconstruct if ReconstructData fails, as it might provide more general recovery
		// though ReconstructData is usually what we want.
		// Let's check if data shards are OK first.
		ok, _ := rs.enc.Verify(shards)
		if !ok {
			 err = rs.enc.Reconstruct(shards) // Attempt full reconstruction
			 if err != nil {
				return nil, fmt.Errorf("Reed-Solomon decoding failed after attempting ReconstructData and Reconstruct: %w", err)
			 }
		}
	}

	reconstructed := make([]Packet, rs.dataShards)
	for i := 0; i < rs.dataShards; i++ {
		if shards[i] == nil { // Should not happen if ReconstructData/Reconstruct succeeded
			 return nil, fmt.Errorf("RS Decode: data shard %d is unexpectedly nil after reconstruction", i)
		}
		reconstructed[i] = Packet(shards[i])
	}
	return reconstructed, nil
}
