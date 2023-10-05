package device

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
)

func appendJunk(writer *bytes.Buffer, size int) error {
	headerJunk, err := randomJunkWithSize(size)
	if err != nil {
		return fmt.Errorf("failed to create header junk: %v", err)
	}
	_, err = writer.Write(headerJunk)
	if err != nil {
		return fmt.Errorf("failed to write header junk: %v", err)
	}
	return nil
}

func randomJunkWithSize(size int) ([]byte, error) {
	junk := make([]byte, size)
	_, err := crand.Read(junk)
	return junk, err
}
