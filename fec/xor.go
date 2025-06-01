package fec

import (
	"errors"
	"fmt"
)

// xorProtector implements FECProtector for simple XOR FEC.
// Assumes M data packets, 1 parity packet. Needs M packets to reconstruct.
type xorProtector struct {
	dataShards int // Number of data packets
}

// NewXORProtector creates a new XOR FEC scheme.
// dataShards: number of original data packets to protect together.
func NewXORProtector(dataShards int) (FECProtector, error) {
	if dataShards <= 0 {
		return nil, errors.New("number of data shards must be positive for XOR FEC")
	}
	return &xorProtector{dataShards: dataShards}, nil
}

func (x *xorProtector) Algorithm() FECAlgorithmType {
	return XOR
}

func (x *xorProtector) NumDataShards() int {
	return x.dataShards
}

func (x *xorProtector) NumParityShards() int {
	return 1 // XOR typically produces 1 parity shard
}

func (x *xorProtector) TotalShards() int {
	return x.dataShards + 1
}

func (x *xorProtector) Encode(sourcePackets []Packet) ([]Packet, error) {
	if len(sourcePackets) != x.dataShards {
		return nil, fmt.Errorf("XOR Encode: expected %d source packets, got %d", x.dataShards, len(sourcePackets))
	}

	if x.dataShards == 0 {
		return []Packet{}, nil // No data, no parity
	}

	// Determine max length for consistent parity packet size
	maxLength := 0
	for _, p := range sourcePackets {
		if p == nil {
			 return nil, errors.New("XOR Encode: nil source packet provided")
		}
		if len(p) > maxLength {
			maxLength = len(p)
		}
	}

	parityPacket := make(Packet, maxLength)
	tempPaddedPacket := make(Packet, maxLength) // Buffer for padding

	for _, p := range sourcePackets {
		copy(tempPaddedPacket, p) // Copy original packet
		// Pad with zeros if shorter than maxLength
		for i := len(p); i < maxLength; i++ {
			tempPaddedPacket[i] = 0
		}
		for i := 0; i < maxLength; i++ {
			parityPacket[i] ^= tempPaddedPacket[i]
		}
	}

	output := make([]Packet, x.dataShards+1)
	copy(output, sourcePackets)
	output[x.dataShards] = parityPacket
	return output, nil
}

func (x *xorProtector) Decode(receivedPackets []Packet) ([]Packet, error) {
	if len(receivedPackets) != x.dataShards+1 {
		return nil, fmt.Errorf("XOR Decode: expected %d total packets (data+parity), got %d", x.dataShards+1, len(receivedPackets))
	}

	missingIndices := []int{}
	validPackets := 0
	maxLength := 0

	for i, p := range receivedPackets {
		if p != nil {
			validPackets++
			if len(p) > maxLength {
				maxLength = len(p)
			}
		} else {
			missingIndices = append(missingIndices, i)
		}
	}

	if len(missingIndices) == 0 { // All packets present
		return receivedPackets[:x.dataShards], nil
	}

	if len(missingIndices) > 1 {
		return nil, fmt.Errorf("XOR Decode: too many missing packets (%d), can only reconstruct 1", len(missingIndices))
	}

	if validPackets < x.dataShards {
		 return nil, fmt.Errorf("XOR Decode: not enough valid packets (%d) to reconstruct, need %d", validPackets, x.dataShards)
	}


	missingIndex := missingIndices[0]
	reconstructedPacket := make(Packet, maxLength)
	tempPaddedPacket := make(Packet, maxLength)

	for i, p := range receivedPackets {
		if i == missingIndex || p == nil { // p == nil check handles if more than 1 was nil, though caught above
			continue
		}
		copy(tempPaddedPacket, p)
		for j := len(p); j < maxLength; j++ { // Pad if necessary
			tempPaddedPacket[j] = 0
		}
		for j := 0; j < maxLength; j++ {
			reconstructedPacket[j] ^= tempPaddedPacket[j]
		}
	}

	// Place reconstructed packet in its original position
	outputPackets := make([]Packet, x.dataShards)
	currentSourceIndex := 0
	for i := 0; i < x.dataShards+1 && currentSourceIndex < x.dataShards; i++ {
		if i == missingIndex {
			if i < x.dataShards { // Only fill if the missing packet was a data packet
				 outputPackets[currentSourceIndex] = reconstructedPacket
				 currentSourceIndex++
			}
		} else if i < x.dataShards { // Packet was a data packet and present
			 outputPackets[currentSourceIndex] = receivedPackets[i]
			 currentSourceIndex++
		}
	}
	return outputPackets, nil
}
