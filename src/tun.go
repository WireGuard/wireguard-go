package main

type TUNDevice interface {
	Read([]byte) (int, error)  // read a packet from the device (without any additional headers)
	Write([]byte) (int, error) // writes a packet to the device (without any additional headers)
	MTU() (int, error)         // returns the MTU of the device
	Name() string              // returns the current name
}
