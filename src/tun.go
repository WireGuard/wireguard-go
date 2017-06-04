package main

type TUN interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Name() string
	MTU() uint
}
