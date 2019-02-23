/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync/atomic"
)

/* Atomic Boolean */

const (
	AtomicFalse = int32(iota)
	AtomicTrue
)

type AtomicBool struct {
	int32
}

func (a *AtomicBool) Get() bool {
	return atomic.LoadInt32(&a.int32) == AtomicTrue
}

func (a *AtomicBool) Swap(val bool) bool {
	flag := AtomicFalse
	if val {
		flag = AtomicTrue
	}
	return atomic.SwapInt32(&a.int32, flag) == AtomicTrue
}

func (a *AtomicBool) Set(val bool) {
	flag := AtomicFalse
	if val {
		flag = AtomicTrue
	}
	atomic.StoreInt32(&a.int32, flag)
}

func min(a, b uint) uint {
	if a > b {
		return b
	}
	return a
}

// called from receive
func ecn_rfc6040_egress(inner byte, outer byte) (byte, bool) {
	/*
	+---------+------------------------------------------------+
	|Arriving |            Arriving Outer Header               |
	|   Inner +---------+------------+------------+------------+
	|  Header | Not-ECT | ECT(0)     | ECT(1)     |     CE     |
	+---------+---------+------------+------------+------------+
	| Not-ECT | Not-ECT |Not-ECT(!!!)|Not-ECT(!!!)| <drop>(!!!)|
	|  ECT(0) |  ECT(0) | ECT(0)     | ECT(1)     |     CE     |
	|  ECT(1) |  ECT(1) | ECT(1) (!) | ECT(1)     |     CE     |
	|    CE   |      CE |     CE     |     CE(!!!)|     CE     |
	+---------+---------+------------+------------+------------+
	*/
	innerECN := CongestionExperienced & inner
	outerECN := CongestionExperienced & outer

	switch outerECN {
	case CongestionExperienced:
		switch innerECN {
		case NotECNTransport:
			return 0, true
		}
		return (inner  & (CongestionExperienced ^ 255)) | CongestionExperienced, false
	case ECNTransport1:
		switch innerECN {
		case ECNTransport0:
			return (inner  & (CongestionExperienced ^ 255)) | ECNTransport1, false
		}
	}
	return inner, false
}

// called from send
func ecn_rfc6040_ingress(inner byte, useNormalMode bool) byte {
	/*
	+-----------------+-------------------------------+
	| Incoming Header |    Departing Outer Header     |
	| (also equal to  +---------------+---------------+
	| departing Inner | Compatibility |    Normal     |
	|     Header)     |     Mode      |     Mode      |
	+-----------------+---------------+---------------+
	|    Not-ECT      |   Not-ECT     |   Not-ECT     |
	|     ECT(0)      |   Not-ECT     |    ECT(0)     |
	|     ECT(1)      |   Not-ECT     |    ECT(1)     |
	|       CE        |   Not-ECT     |      CE       |
	+-----------------+---------------+---------------+
	*/
	if !useNormalMode {
		inner &= (CongestionExperienced ^ 255)
	}

	return inner
}

func ecn_rfc6040_enabled(tos byte) bool {
	return (CongestionExperienced & tos) == ECNTransport0
}
