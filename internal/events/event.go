package events

import (
	"sync"
)

type Event interface {
	Contains(int) bool
	Processed()
	WaitForProcessed()
}

type EventStruct struct {
	code int
	lock sync.Mutex
}

func (event EventStruct) Contains(code int) bool {
	return event.code&code != 0
}

func (event *EventStruct) WaitForProcessed() {
	event.lock.Lock()
}

func (event *EventStruct) Processed() {
	event.lock.Unlock()
}

func NewEvent(code int) Event {
	event := &EventStruct{
		code: code,
	}
	event.lock.Lock()
	return event
}
