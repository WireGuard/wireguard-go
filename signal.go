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

func (s *Signal) Close() {
	close(s.C)
}

func (s *Signal) Disable() {
	s.enabled.Set(false)
	s.Clear()
}

func (s *Signal) Enable() {
	s.enabled.Set(true)
}

/* Unblock exactly one listener
 */
func (s *Signal) Send() {
	if s.enabled.Get() {
		select {
		case s.C <- struct{}{}:
		default:
		}
	}
}

/* Clear the signal if already fired
 */
func (s Signal) Clear() {
	select {
	case <-s.C:
	default:
	}
}

/* Unblocks all listeners (forever)
 */
func (s Signal) Broadcast() {
	if s.enabled.Get() {
		close(s.C)
	}
}

/* Wait for the signal
 */
func (s Signal) Wait() chan struct{} {
	return s.C
}
