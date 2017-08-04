package main

/*
 * The default MTU of the new device must be 1420
 */

const DefaultMTU = 1420

type TUNDevice interface {
	Read([]byte) (int, error)  // read a packet from the device (without any additional headers)
	Write([]byte) (int, error) // writes a packet to the device (without any additional headers)
	IsUp() (bool, error)       // is the interface up?
	MTU() (int, error)         // returns the MTU of the device
	Name() string              // returns the current name
}
