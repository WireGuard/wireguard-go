package main

import (
	"bytes"
	"os"
	"testing"
)

/* Helpers for writing unit tests
 */

type DummyTUN struct {
	name    string
	mtu     int
	packets chan []byte
	events  chan TUNEvent
}

func (tun *DummyTUN) File() *os.File {
	return nil
}

func (tun *DummyTUN) Name() string {
	return tun.name
}

func (tun *DummyTUN) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *DummyTUN) Write(d []byte) (int, error) {
	tun.packets <- d
	return len(d), nil
}

func (tun *DummyTUN) Close() error {
	return nil
}

func (tun *DummyTUN) Events() chan TUNEvent {
	return tun.events
}

func (tun *DummyTUN) Read(d []byte) (int, error) {
	t := <-tun.packets
	copy(d, t)
	return len(t), nil
}

func CreateDummyTUN(name string) (TUNDevice, error) {
	var dummy DummyTUN
	dummy.mtu = 0
	dummy.packets = make(chan []byte, 100)
	return &dummy, nil
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a []byte, b []byte) {
	if bytes.Compare(a, b) != 0 {
		t.Fatal(a, "!=", b)
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun, _ := CreateDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, logger)
	device.SetPrivateKey(sk)
	return device
}
