/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//sys	setupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator *uint16, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName *uint16, reserved uintptr) (handle DevInfo, err error) [failretval==DevInfo(windows.InvalidHandle)] = setupapi.SetupDiGetClassDevsExW
//sys	SetupDiDestroyDeviceInfoList(DeviceInfoSet DevInfo) (err error) = setupapi.SetupDiDestroyDeviceInfoList
//sys	setupDiGetDeviceInfoListDetail(DeviceInfoSet DevInfo, DeviceInfoSetDetailData *_SP_DEVINFO_LIST_DETAIL_DATA) (err error) = setupapi.SetupDiGetDeviceInfoListDetailW
//sys	setupDiEnumDeviceInfo(DeviceInfoSet DevInfo, MemberIndex uint32, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiEnumDeviceInfo
//sys	setupDiOpenDevRegKey(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key windows.Handle, err error) [failretval==windows.InvalidHandle] = setupapi.SetupDiOpenDevRegKey

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
	var _p0 _SP_DEVINFO_LIST_DETAIL_DATA
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

// SetupDiEnumDeviceInfo function returns a SP_DEVINFO_DATA structure that specifies a device information element in a device information set.
func SetupDiEnumDeviceInfo(DeviceInfoSet DevInfo, MemberIndex int, data *SP_DEVINFO_DATA) error {
	data.Size = uint32(unsafe.Sizeof(*data))
	return setupDiEnumDeviceInfo(DeviceInfoSet, uint32(MemberIndex), data)
}

// SetupDiOpenDevRegKey function opens a registry key for device-specific configuration information.
func SetupDiOpenDevRegKey(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key registry.Key, err error) {
	handle, err := setupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, samDesired)
	return registry.Key(handle), err
}
