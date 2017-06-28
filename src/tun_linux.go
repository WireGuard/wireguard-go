package main

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

/* Implementation of the TUN device interface for linux
 */

const CloneDevicePath = "/dev/net/tun"

const (
	IFF_NO_PI = 0x1000
	IFF_TUN   = 0x1
	IFNAMSIZ  = 0x10
	TUNSETIFF = 0x400454CA
)

type NativeTun struct {
	fd   *os.File
	name string
	mtu  uint
}

func (tun *NativeTun) Name() string {
	return tun.name
}

func (tun *NativeTun) MTU() uint {
	return tun.mtu
}

func (tun *NativeTun) Write(d []byte) (int, error) {
	return tun.fd.Write(d)
}

func (tun *NativeTun) Read(d []byte) (int, error) {
	return tun.fd.Read(d)
}

func CreateTUN(name string) (TUNDevice, error) {
	// Open clone device
	fd, err := os.OpenFile(CloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// Prepare ifreq struct
	var ifr [128]byte
	var flags uint16 = IFF_TUN | IFF_NO_PI
	nameBytes := []byte(name)
	if len(nameBytes) >= IFNAMSIZ {
		return nil, errors.New("Name size too long")
	}
	copy(ifr[:], nameBytes)
	binary.LittleEndian.PutUint16(ifr[16:], flags)

	// Create new device
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd.Fd()), uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return nil, errors.New("Failed to create tun, ioctl call failed")
	}

	// Read name of interface
	newName := string(ifr[:])
	newName = newName[:strings.Index(newName, "\000")]
	return &NativeTun{
		fd:   fd,
		name: newName,
	}, nil
}
