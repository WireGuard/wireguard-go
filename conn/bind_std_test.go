package conn

import "testing"

func TestStdNetBindReceiveFuncAfterClose(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bind.Close()
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 1)
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	for _, fn := range fns {
		// The ReceiveFuncs must not access conn-related fields on StdNetBind
		// unguarded. Close() nils the conn-related fields resulting in a panic
		// if they violate the mutex.
		fn(bufs, sizes, eps)
	}
}
