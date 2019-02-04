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

//sys	setupDiClassNameFromGuidEx(ClassGUID *windows.GUID, ClassName *uint16, ClassNameSize uint32, RequiredSize *uint32, MachineName *uint16, Reserved uintptr) (err error) = setupapi.SetupDiClassNameFromGuidExW
//sys	setupDiClassGuidsFromNameEx(ClassName *uint16, ClassGuidList *windows.GUID, ClassGuidListSize uint32, RequiredSize *uint32, MachineName *uint16, Reserved uintptr) (err error) = setupapi.SetupDiClassGuidsFromNameExW
//sys	setupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator *uint16, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName *uint16, reserved uintptr) (handle DevInfo, err error) [failretval==DevInfo(windows.InvalidHandle)] = setupapi.SetupDiGetClassDevsExW
//sys	SetupDiDestroyDeviceInfoList(DeviceInfoSet DevInfo) (err error) = setupapi.SetupDiDestroyDeviceInfoList
//sys	setupDiGetDeviceInfoListDetail(DeviceInfoSet DevInfo, DeviceInfoSetDetailData *_SP_DEVINFO_LIST_DETAIL_DATA) (err error) = setupapi.SetupDiGetDeviceInfoListDetailW
//sys	setupDiEnumDeviceInfo(DeviceInfoSet DevInfo, MemberIndex uint32, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiEnumDeviceInfo
//sys	setupDiOpenDevRegKey(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key windows.Handle, err error) [failretval==windows.InvalidHandle] = setupapi.SetupDiOpenDevRegKey
//sys	setupDiGetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *_SP_DEVINSTALL_PARAMS) (err error) = setupapi.SetupDiGetDeviceInstallParamsW
//sys	setupDiSetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *_SP_DEVINSTALL_PARAMS) (err error) = setupapi.SetupDiSetDeviceInstallParamsW
//sys	SetupDiGetClassInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, ClassInstallParams *SP_CLASSINSTALL_HEADER, ClassInstallParamsSize uint32, RequiredSize *uint32) (err error) = setupapi.SetupDiGetClassInstallParamsW
//sys	SetupDiSetClassInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, ClassInstallParams *SP_CLASSINSTALL_HEADER, ClassInstallParamsSize uint32) (err error) = setupapi.SetupDiSetClassInstallParamsW
//sys	SetupDiCallClassInstaller(InstallFunction DI_FUNCTION, DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiCallClassInstaller

// SetupDiClassNameFromGuidEx function retrieves the class name associated with a class GUID. The class can be installed on a local or remote computer.
func SetupDiClassNameFromGuidEx(ClassGUID *windows.GUID, MachineName string) (ClassName string, err error) {
	var _p0 [MAX_CLASS_NAME_LEN]uint16

	var _p1 *uint16
	if MachineName != "" {
		_p1, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}

	err = setupDiClassNameFromGuidEx(ClassGUID, &_p0[0], MAX_CLASS_NAME_LEN, nil, _p1, 0)
	if err != nil {
		return
	}

	ClassName = windows.UTF16ToString(_p0[:])
	return
}

// SetupDiClassGuidsFromNameEx function retrieves the GUIDs associated with the specified class name. This resulting list contains the classes currently installed on a local or remote computer.
func SetupDiClassGuidsFromNameEx(ClassName string, MachineName string) (ClassGuidList []windows.GUID, err error) {
	_p0, err := syscall.UTF16PtrFromString(ClassName)
	if err != nil {
		return
	}

	var _p1 [4]windows.GUID
	var _p1reqSize uint32

	var _p2 *uint16
	if MachineName != "" {
		_p2, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}

	err = setupDiClassGuidsFromNameEx(_p0, &_p1[0], 4, &_p1reqSize, _p2, 0)
	if err == nil {
		// The GUID array was sufficiently big. Return its slice.
		return _p1[:_p1reqSize], nil
	}

	if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_INSUFFICIENT_BUFFER {
		// The GUID array was too small. Now that we got the required size, create another one big enough and retry.
		_p1 := make([]windows.GUID, _p1reqSize)
		err = setupDiClassGuidsFromNameEx(_p0, &_p1[0], _p1reqSize, &_p1reqSize, _p2, 0)
		if err == nil {
			return _p1[:_p1reqSize], nil
		}
	}

	return
}

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

// SetupDiGetDeviceInstallParams function retrieves device installation parameters for a device information set or a particular device information element.
func SetupDiGetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA) (data *DevInstallParams, err error) {
	var DeviceInstallParams _SP_DEVINSTALL_PARAMS
	DeviceInstallParams.Size = uint32(unsafe.Sizeof(DeviceInstallParams))

	err = setupDiGetDeviceInstallParams(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams)
	if err != nil {
		return
	}

	data = &DevInstallParams{
		Flags:                    DeviceInstallParams.Flags,
		FlagsEx:                  DeviceInstallParams.FlagsEx,
		hwndParent:               DeviceInstallParams.hwndParent,
		InstallMsgHandler:        DeviceInstallParams.InstallMsgHandler,
		InstallMsgHandlerContext: DeviceInstallParams.InstallMsgHandlerContext,
		FileQueue:                DeviceInstallParams.FileQueue,
		DriverPath:               windows.UTF16ToString(DeviceInstallParams.DriverPath[:]),
	}
	return
}

// SetupDiSetDeviceInstallParams function sets device installation parameters for a device information set or a particular device information element.
func SetupDiSetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *DevInstallParams) (err error) {
	data := _SP_DEVINSTALL_PARAMS{
		Flags:                    DeviceInstallParams.Flags,
		FlagsEx:                  DeviceInstallParams.FlagsEx,
		hwndParent:               DeviceInstallParams.hwndParent,
		InstallMsgHandler:        DeviceInstallParams.InstallMsgHandler,
		InstallMsgHandlerContext: DeviceInstallParams.InstallMsgHandlerContext,
		FileQueue:                DeviceInstallParams.FileQueue,
	}
	data.Size = uint32(unsafe.Sizeof(data))

	_p0, err := syscall.UTF16FromString(DeviceInstallParams.DriverPath)
	if err != nil {
		return
	}
	copy(data.DriverPath[:], _p0)

	return setupDiSetDeviceInstallParams(DeviceInfoSet, DeviceInfoData, &data)
}
