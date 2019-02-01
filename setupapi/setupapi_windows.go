/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys	setupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator *uint16, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName *uint16, reserved uintptr) (handle DevInfo, err error) [failretval==DevInfo(windows.InvalidHandle)] = setupapi.SetupDiGetClassDevsExW
//sys	SetupDiDestroyDeviceInfoList(DeviceInfoSet DevInfo) (err error) = setupapi.SetupDiDestroyDeviceInfoList
//sys	setupDiGetDeviceInfoListDetail(DeviceInfoSet DevInfo, DeviceInfoSetDetailData *SP_DEVINFO_LIST_DETAIL_DATA) (err error) = setupapi.SetupDiGetDeviceInfoListDetailW

// SetupDiGetClassDevsEx function returns a handle to a device information set that contains requested device information elements for a local or a remote computer.
func SetupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator string, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName string) (handle DevInfo, err error) {
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
	return setupDiGetClassDevsEx(ClassGUID, _p0, hwndParent, Flags, DeviceInfoSet, _p1, 0)
}

// SetupDiGetDeviceInfoListDetail function retrieves information associated with a device information set including the class GUID, remote computer handle, and remote computer name.
func SetupDiGetDeviceInfoListDetail(DeviceInfoSet DevInfo) (data *DevInfoListDetailData, err error) {
	var _p0 SP_DEVINFO_LIST_DETAIL_DATA
	_p0.Size = uint32(unsafe.Sizeof(_p0))

	err = setupDiGetDeviceInfoListDetail(DeviceInfoSet, &_p0)
	if err != nil {
		return
	}

	data = &DevInfoListDetailData{
		ClassGUID:           _p0.ClassGUID,
		RemoteMachineHandle: _p0.RemoteMachineHandle,
		RemoteMachineName:   windows.UTF16ToString(_p0.RemoteMachineName[:]),
	}
	return
}
