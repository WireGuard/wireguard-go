package main

/*
 * The default MTU of the new device must be 1420
 */

const DefaultMTU = 1420

type TUNEvent int

const (
	TUNEventUp = 1 << iota
	TUNEventDown
	TUNEventMTUUpdate
)

type TUNDevice interface {
	Read([]byte) (int, error)  // read a packet from the device (without any additional headers)
	Write([]byte) (int, error) // writes a packet to the device (without any additional headers)
	MTU() (int, error)         // returns the MTU of the device
	Name() string              // returns the current name
	Events() chan TUNEvent     // returns a constant channel of events related to the device
	Close() error              // stops the device and closes the event channel
}
