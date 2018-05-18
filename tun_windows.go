/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

/* Relies on the OpenVPN TAP-Windows driver (NDIS 6 version)
 *
 * https://github.com/OpenVPN/tap-windows
 */

type NativeTUN struct {
	fd     windows.Handle
	rl     sync.Mutex
	wl     sync.Mutex
	ro     *windows.Overlapped
	wo     *windows.Overlapped
	events chan TUNEvent
	name   string
}

const (
	METHOD_BUFFERED = 0
	ComponentID     = "tap0901" // tap0801
)

func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

func TAP_CONTROL_CODE(request, method uint32) uint32 {
	return ctl_code(file_device_unknown, request, method, 0)
}

var (
	errIfceNameNotFound = errors.New("Failed to find the name of interface")

	TAP_IOCTL_GET_MAC               = TAP_CONTROL_CODE(1, METHOD_BUFFERED)
	TAP_IOCTL_GET_VERSION           = TAP_CONTROL_CODE(2, METHOD_BUFFERED)
	TAP_IOCTL_GET_MTU               = TAP_CONTROL_CODE(3, METHOD_BUFFERED)
	TAP_IOCTL_GET_INFO              = TAP_CONTROL_CODE(4, METHOD_BUFFERED)
	TAP_IOCTL_CONFIG_POINT_TO_POINT = TAP_CONTROL_CODE(5, METHOD_BUFFERED)
	TAP_IOCTL_SET_MEDIA_STATUS      = TAP_CONTROL_CODE(6, METHOD_BUFFERED)
	TAP_IOCTL_CONFIG_DHCP_MASQ      = TAP_CONTROL_CODE(7, METHOD_BUFFERED)
	TAP_IOCTL_GET_LOG_LINE          = TAP_CONTROL_CODE(8, METHOD_BUFFERED)
	TAP_IOCTL_CONFIG_DHCP_SET_OPT   = TAP_CONTROL_CODE(9, METHOD_BUFFERED)
	TAP_IOCTL_CONFIG_TUN            = TAP_CONTROL_CODE(10, METHOD_BUFFERED)

	file_device_unknown = uint32(0x00000022)
	nCreateEvent,
	nResetEvent,
	nGetOverlappedResult uintptr
)

func init() {
	k32, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		panic("LoadLibrary " + err.Error())
	}
	defer windows.FreeLibrary(k32)
	nCreateEvent = getProcAddr(k32, "CreateEventW")
	nResetEvent = getProcAddr(k32, "ResetEvent")
	nGetOverlappedResult = getProcAddr(k32, "GetOverlappedResult")
}

/* implementation of the read/write/closer interface */

func getProcAddr(lib windows.Handle, name string) uintptr {
	addr, err := windows.GetProcAddress(lib, name)
	if err != nil {
		panic(name + " " + err.Error())
	}
	return addr
}

func resetEvent(h windows.Handle) error {
	r, _, err := syscall.Syscall(nResetEvent, 1, uintptr(h), 0, 0)
	if r == 0 {
		return err
	}
	return nil
}

func getOverlappedResult(h windows.Handle, overlapped *windows.Overlapped) (int, error) {
	var n int
	r, _, err := syscall.Syscall6(
		nGetOverlappedResult,
		4,
		uintptr(h),
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&n)), 1, 0, 0)

	if r == 0 {
		return n, err
	}
	return n, nil
}

func newOverlapped() (*windows.Overlapped, error) {
	var overlapped windows.Overlapped
	r, _, err := syscall.Syscall6(nCreateEvent, 4, 0, 1, 0, 0, 0, 0)
	if r == 0 {
		return nil, err
	}
	overlapped.HEvent = windows.Handle(r)
	return &overlapped, nil
}

func (f *NativeTUN) Events() chan TUNEvent {
	return f.events
}

func (f *NativeTUN) Close() error {
	close(f.events)
	err := windows.Close(f.fd)
	return err
}

func (f *NativeTUN) Write(b []byte) (int, error) {
	f.wl.Lock()
	defer f.wl.Unlock()

	if err := resetEvent(f.wo.HEvent); err != nil {
		return 0, err
	}
	var n uint32
	err := windows.WriteFile(f.fd, b, &n, f.wo)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return int(n), err
	}
	return getOverlappedResult(f.fd, f.wo)
}

func (f *NativeTUN) Read(b []byte) (int, error) {
	f.rl.Lock()
	defer f.rl.Unlock()

	if err := resetEvent(f.ro.HEvent); err != nil {
		return 0, err
	}
	var done uint32
	err := windows.ReadFile(f.fd, b, &done, f.ro)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return int(done), err
	}
	return getOverlappedResult(f.fd, f.ro)
}

func getdeviceid(
	targetComponentId string,
	targetDeviceName string,
) (deviceid string, err error) {

	getName := func(instanceId string) (string, error) {
		path := fmt.Sprintf(
			`SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\%s\Connection`,
			instanceId,
		)

		key, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			path,
			registry.READ,
		)

		if err != nil {
			return "", err
		}
		defer key.Close()

		val, _, err := key.GetStringValue("Name")
		key.Close()
		return val, err
	}

	getInstanceId := func(keyName string) (string, string, error) {
		path := fmt.Sprintf(
			`SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\%s`,
			keyName,
		)

		key, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			path,
			registry.READ,
		)

		if err != nil {
			return "", "", err
		}
		defer key.Close()

		componentId, _, err := key.GetStringValue("ComponentId")
		if err != nil {
			return "", "", err
		}

		instanceId, _, err := key.GetStringValue("NetCfgInstanceId")

		return componentId, instanceId, err
	}

	// find list of all network devices

	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`,
		registry.READ,
	)

	if err != nil {
		return "", fmt.Errorf("Failed to open the adapter registry, TAP driver may be not installed, %v", err)
	}

	defer k.Close()

	keys, err := k.ReadSubKeyNames(-1)

	if err != nil {
		return "", err
	}

	// look for matching component id and name

	var componentFound bool

	for _, v := range keys {

		componentId, instanceId, err := getInstanceId(v)
		if err != nil || componentId != targetComponentId {
			continue
		}

		componentFound = true

		deviceName, err := getName(instanceId)
		if err != nil || deviceName != targetDeviceName {
			continue
		}

		return instanceId, nil
	}

	// provide a descriptive error message

	if componentFound {
		return "", fmt.Errorf("Unable to find tun/tap device with name = %s", targetDeviceName)
	}

	return "", fmt.Errorf(
		"Unable to find device in registry with ComponentId = %s, is tap-windows installed?",
		targetComponentId,
	)
}

// setStatus is used to bring up or bring down the interface
func setStatus(fd windows.Handle, status bool) error {
	var code [4]byte
	if status {
		binary.LittleEndian.PutUint32(code[:], 1)
	}

	var bytesReturned uint32
	rdbbuf := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	return windows.DeviceIoControl(
		fd,
		TAP_IOCTL_SET_MEDIA_STATUS,
		&code[0],
		uint32(4),
		&rdbbuf[0],
		uint32(len(rdbbuf)),
		&bytesReturned,
		nil,
	)
}

/* When operating in TUN mode we must assign an ip address & subnet to the device.
 *
 */
func setTUN(fd windows.Handle, network string) error {
	var bytesReturned uint32
	rdbbuf := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	localIP, remoteNet, err := net.ParseCIDR(network)

	if err != nil {
		return fmt.Errorf("Failed to parse network CIDR in config, %v", err)
	}

	if localIP.To4() == nil {
		return fmt.Errorf("Provided network(%s) is not a valid IPv4 address", network)
	}

	var param [12]byte

	copy(param[0:4], localIP.To4())
	copy(param[4:8], remoteNet.IP.To4())
	copy(param[8:12], remoteNet.Mask)

	return windows.DeviceIoControl(
		fd,
		TAP_IOCTL_CONFIG_TUN,
		&param[0],
		uint32(12),
		&rdbbuf[0],
		uint32(len(rdbbuf)),
		&bytesReturned,
		nil,
	)
}

func (tun *NativeTUN) MTU() (int, error) {
	var mtu [4]byte
	var bytesReturned uint32
	err := windows.DeviceIoControl(
		tun.fd,
		TAP_IOCTL_GET_MTU,
		&mtu[0],
		uint32(len(mtu)),
		&mtu[0],
		uint32(len(mtu)),
		&bytesReturned,
		nil,
	)
	val := binary.LittleEndian.Uint32(mtu[:])
	return int(val), err
}

func (tun *NativeTUN) Name() string {
	return tun.name
}

func CreateTUN(name string) (TUNDevice, error) {

	// find the device in registry.

	deviceid, err := getdeviceid(ComponentID, name)
	if err != nil {
		return nil, err
	}
	path := "\\\\.\\Global\\" + deviceid + ".tap"
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	// create TUN device

	handle, err := windows.CreateFile(
		pathp,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED,
		0,
	)

	if err != nil {
		return nil, err
	}

	ro, err := newOverlapped()
	if err != nil {
		windows.Close(handle)
		return nil, err
	}

	wo, err := newOverlapped()
	if err != nil {
		windows.Close(handle)
		return nil, err
	}

	tun := &NativeTUN{
		fd:     handle,
		name:   name,
		ro:     ro,
		wo:     wo,
		events: make(chan TUNEvent, 5),
	}

	// find addresses of interface
	// TODO: fix this hack, the question is how

	inter, err := net.InterfaceByName(name)
	if err != nil {
		windows.Close(handle)
		return nil, err
	}

	addrs, err := inter.Addrs()
	if err != nil {
		windows.Close(handle)
		return nil, err
	}

	var ip net.IP
	for _, addr := range addrs {
		ip = func() net.IP {
			switch v := addr.(type) {
			case *net.IPNet:
				return v.IP.To4()
			case *net.IPAddr:
				return v.IP.To4()
			}
			return nil
		}()
		if ip != nil {
			break
		}
	}

	if ip == nil {
		windows.Close(handle)
		return nil, errors.New("No IPv4 address found for interface")
	}

	// bring up device.

	if err := setStatus(handle, true); err != nil {
		windows.Close(handle)
		return nil, err
	}

	// set tun mode

	mask := ip.String() + "/0"
	if err := setTUN(handle, mask); err != nil {
		windows.Close(handle)
		return nil, err
	}

	// start listener

	go func(native *NativeTUN, ifname string) {
		// TODO: Fix this very niave implementation
		var (
			statusUp  bool
			statusMTU int
		)

		for ; ; time.Sleep(time.Second) {
			intr, err := net.InterfaceByName(name)
			if err != nil {
				// TODO: handle
				return
			}

			// Up / Down event
			up := (intr.Flags & net.FlagUp) != 0
			if up != statusUp && up {
				native.events <- TUNEventUp
			}
			if up != statusUp && !up {
				native.events <- TUNEventDown
			}
			statusUp = up

			// MTU changes
			if intr.MTU != statusMTU {
				native.events <- TUNEventMTUUpdate
			}
			statusMTU = intr.MTU
		}
	}(tun, name)

	return tun, nil
}
