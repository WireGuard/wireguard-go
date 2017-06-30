package main

func min(a uint, b uint) uint {
	if a > b {
		return b
	}
	return a
}

func sendSignal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}
