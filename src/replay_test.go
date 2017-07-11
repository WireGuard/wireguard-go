package main

import (
	"testing"
)

/* Ported from the linux kernel implementation
 *
 *
 */

func TestReplay(t *testing.T) {
	var filter ReplayFilter

	T_LIM := CounterWindowSize + 1

	testNumber := 0
	T := func(n uint64, v bool) {
		testNumber++
		if filter.ValidateCounter(n) != v {
			t.Fatal("Test", testNumber, "failed", n, v)
		}
	}

	filter.Init()

	/*  1 */ T(0, true)
	/*  2 */ T(1, true)
	/*  3 */ T(1, false)
	/*  4 */ T(9, true)
	/*  5 */ T(8, true)
	/*  6 */ T(7, true)
	/*  7 */ T(7, false)
	/*  8 */ T(T_LIM, true)
	/*  9 */ T(T_LIM-1, true)
	/* 10 */ T(T_LIM-1, false)
	/* 11 */ T(T_LIM-2, true)
	/* 12 */ T(2, true)
	/* 13 */ T(2, false)
	/* 14 */ T(T_LIM+16, true)
	/* 15 */ T(3, false)
	/* 16 */ T(T_LIM+16, false)
	/* 17 */ T(T_LIM*4, true)
	/* 18 */ T(T_LIM*4-(T_LIM-1), true)
	/* 19 */ T(10, false)
	/* 20 */ T(T_LIM*4-T_LIM, false)
	/* 21 */ T(T_LIM*4-(T_LIM+1), false)
	/* 22 */ T(T_LIM*4-(T_LIM-2), true)
	/* 23 */ T(T_LIM*4+1-T_LIM, false)
	/* 24 */ T(0, false)
	/* 25 */ T(RejectAfterMessages, false)
	/* 26 */ T(RejectAfterMessages-1, true)
	/* 27 */ T(RejectAfterMessages, false)
	/* 28 */ T(RejectAfterMessages-1, false)
	/* 29 */ T(RejectAfterMessages-2, true)
	/* 30 */ T(RejectAfterMessages+1, false)
	/* 31 */ T(RejectAfterMessages+2, false)
	/* 32 */ T(RejectAfterMessages-2, false)
	/* 33 */ T(RejectAfterMessages-3, true)
	/* 34 */ T(0, false)

	t.Log("Bulk test 1")
	filter.Init()
	testNumber = 0
	for i := uint64(1); i <= CounterWindowSize; i++ {
		T(i, true)
	}
	T(0, true)
	T(0, false)

	t.Log("Bulk test 2")
	filter.Init()
	testNumber = 0
	for i := uint64(2); i <= CounterWindowSize+1; i++ {
		T(i, true)
	}
	T(1, true)
	T(0, false)

	t.Log("Bulk test 3")
	filter.Init()
	testNumber = 0
	for i := CounterWindowSize + 1; i > 0; i-- {
		T(i, true)
	}

	t.Log("Bulk test 4")
	filter.Init()
	testNumber = 0
	for i := CounterWindowSize + 2; i > 1; i-- {
		T(i, true)
	}
	T(0, false)

	t.Log("Bulk test 5")
	filter.Init()
	testNumber = 0
	for i := CounterWindowSize; i > 0; i-- {
		T(i, true)
	}
	T(CounterWindowSize+1, true)
	T(0, false)

	t.Log("Bulk test 6")
	filter.Init()
	testNumber = 0
	for i := CounterWindowSize; i > 0; i-- {
		T(i, true)
	}
	T(0, true)
	T(CounterWindowSize+1, true)
}
