package tun

import (
	"errors"
	"os"
	"sync"
)

type MemoryTun struct {
	in        chan []byte
	out       chan []byte
	events    chan Event
	mtu       int
	batchSize int

	closed bool
	mu     sync.Mutex
}

func (t *MemoryTun) BatchSize() int {
	return t.batchSize
}

func (t *MemoryTun) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.closed {
		close(t.in)
		close(t.out)
		t.closed = true
	}
	return nil
}

func (t *MemoryTun) Events() <-chan Event {
	return t.events
}

func (t *MemoryTun) File() *os.File {
	return nil
}

func (t *MemoryTun) MTU() (int, error) {
	return t.mtu, nil
}

func (t *MemoryTun) Name() (string, error) {
	return "snapTunnel", nil
}

func (t *MemoryTun) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	pkt, ok := <-t.in
	if !ok {
		return n, errors.New("tun closed")
	}
	dst := bufs[0][offset:]

	copied := copy(dst, pkt)
	sizes[0] = copied

	n++
	for i := 1; i < len(bufs); i++ {
		select {
		case pkt, ok := <-t.in:
			if !ok {
				return n, errors.New("tun closed")
			}
			dst := bufs[i][offset:]

			copied := copy(dst, pkt)
			sizes[i] = copied

			n++
		default:
			return n, nil
		}

	}
	return n, nil
}

func (t *MemoryTun) Write(bufs [][]byte, offset int) (int, error) {
	n := 0
	for i := range bufs {
		if len(bufs[i]) <= offset {
			continue // malformed packet
		}

		pkt := make([]byte, len(bufs[i][offset:]))
		copy(pkt, bufs[i][offset:])

		t.out <- pkt
		n++
	}

	return n, nil
}

func CreateInMemoryTunnel(mtu int, channelSize int, batchSize int) *MemoryTun {
	tun := &MemoryTun{
		in:        make(chan []byte, channelSize),
		out:       make(chan []byte, channelSize),
		events:    make(chan Event, 100),
		mtu:       mtu,
		batchSize: batchSize,
	}

	return tun
}
