package main

type TUNDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Name() string
	MTU() uint
}
