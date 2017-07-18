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

type NativeTun struct {
	fd   *os.File
	name string
}

func (tun *NativeTun) Name() string {
	return tun.name
}

func (tun *NativeTun) setMTU(n int) error {

	// open datagram socket

	fd, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return err
	}

	defer syscall.Close(fd)

	// do ioctl call

	var ifr [64]byte
	copy(ifr[:], tun.name)
	binary.LittleEndian.PutUint32(ifr[16:20], uint32(n))
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return errors.New("Failed to set MTU of TUN device")
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {

	// open datagram socket

	fd, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return 0, err
	}

	defer syscall.Close(fd)

	// do ioctl call

	var ifr [64]byte
	copy(ifr[:], tun.name)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, errors.New("Failed to get MTU of TUN device")
	}

	// convert result to signed 32-bit int

	val := binary.LittleEndian.Uint32(ifr[16:20])
	if val >= (1 << 31) {
		return int(val-(1<<31)) - (1 << 31), nil
	}
	return int(val), nil
}

func (tun *NativeTun) Write(d []byte) (int, error) {
	return tun.fd.Write(d)
}

func (tun *NativeTun) Read(d []byte) (int, error) {
	return tun.fd.Read(d)
}

func CreateTUN(name string) (TUNDevice, error) {

	// open clone device

	fd, err := os.OpenFile(CloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// create new device

	var ifr [64]byte
	var flags uint16 = syscall.IFF_TUN | syscall.IFF_NO_PI
	nameBytes := []byte(name)
	if len(nameBytes) >= syscall.IFNAMSIZ {
		return nil, errors.New("Name size too long")
	}
	copy(ifr[:], nameBytes)
	binary.LittleEndian.PutUint16(ifr[16:], flags)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd.Fd()),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return nil, errors.New("Failed to create tun, ioctl call failed")
	}

	// read (new) name of interface

	newName := string(ifr[:])
	newName = newName[:strings.Index(newName, "\000")]
	device := &NativeTun{
		fd:   fd,
		name: newName,
	}

	// set default MTU

	err = device.setMTU(DefaultMTU)
	return device, err
}
