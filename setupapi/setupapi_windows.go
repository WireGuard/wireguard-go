/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	SP_MAX_MACHINENAME_LENGTH = windows.MAX_PATH + 3
)

type DIGCF uint32

const (
	DIGCF_DEFAULT         DIGCF = 0x00000001 // only valid with DIGCF_DEVICEINTERFACE
	DIGCF_PRESENT         DIGCF = 0x00000002
	DIGCF_ALLCLASSES      DIGCF = 0x00000004
	DIGCF_PROFILE         DIGCF = 0x00000008
	DIGCF_DEVICEINTERFACE DIGCF = 0x00000010
)

type DevInfo windows.Handle

// The SetupDiDestroyDeviceInfoList function deletes a device information set and frees all associated memory.
func (h DevInfo) Close() error {
	if h != DevInfo(windows.InvalidHandle) {
		return SetupDiDestroyDeviceInfoList(h)
	}

	return nil
}

//sys	setupDiGetClassDevsEx(ClassGuid *windows.GUID, Enumerator *uint16, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName *uint16, reserved uintptr) (handle DevInfo, err error) [failretval==DevInfo(windows.InvalidHandle)] = setupapi.SetupDiGetClassDevsExW
//sys	SetupDiDestroyDeviceInfoList(DeviceInfoSet DevInfo) (err error) = setupapi.SetupDiDestroyDeviceInfoList

// The SetupDiGetClassDevsEx function returns a handle to a device information set that contains requested device information elements for a local or a remote computer.
func SetupDiGetClassDevsEx(ClassGuid *windows.GUID, Enumerator string, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName string) (handle DevInfo, err error) {
	var _p0 *uint16
	if Enumerator != "" {
		_p0, err = syscall.UTF16PtrFromString(Enumerator)
		if err != nil {
			return
		}
	}
	var _p1 *uint16
	if MachineName != "" {
		_p1, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}
	return setupDiGetClassDevsEx(ClassGuid, _p0, hwndParent, Flags, DeviceInfoSet, _p1, 0)
}
