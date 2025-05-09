package device

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var msgSink MessageInitiation

func BenchmarkMessageInitiationUnmarshal(b *testing.B) {
	packet := make([]byte, MessageInitiationSize)
	reader := bytes.NewReader(packet)
	err := binary.Read(reader, binary.LittleEndian, &msgSink)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("binary.Read", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			reader := bytes.NewReader(packet)
			_ = binary.Read(reader, binary.LittleEndian, &msgSink)
		}
	})

	b.Run("unmarshal", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = msgSink.unmarshal(packet)
		}
	})
}
