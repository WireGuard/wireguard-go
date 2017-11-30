package main

type Signal struct {
	enabled AtomicBool
	C       chan struct{}
}

func NewSignal() (s Signal) {
	s.C = make(chan struct{}, 1)
	s.Enable()
	return
}

func (s *Signal) Disable() {
	s.enabled.Set(false)
	s.Clear()
}

func (s *Signal) Enable() {
	s.enabled.Set(true)
}

func (s *Signal) Send() {
	if s.enabled.Get() {
		select {
		case s.C <- struct{}{}:
		default:
		}
	}
}

func (s Signal) Clear() {
	select {
	case <-s.C:
	default:
	}
}

func (s Signal) Broadcast() {
	close(s.C) // unblocks all selectors
}

func (s Signal) Wait() chan struct{} {
	return s.C
}
