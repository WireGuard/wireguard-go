/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//sys	setupDiCreateDeviceInfoListEx(ClassGUID *windows.GUID, hwndParent uintptr, MachineName *uint16, Reserved uintptr) (handle DevInfo, err error) [failretval==DevInfo(windows.InvalidHandle)] = setupapi.SetupDiCreateDeviceInfoListExW

// SetupDiCreateDeviceInfoListEx function creates an empty device information set on a remote or a local computer and optionally associates the set with a device setup class.
func SetupDiCreateDeviceInfoListEx(ClassGUID *windows.GUID, hwndParent uintptr, MachineName string) (DeviceInfoSet DevInfo, err error) {
	var machineNameUTF16 *uint16
	if MachineName != "" {
		machineNameUTF16, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}
	return setupDiCreateDeviceInfoListEx(ClassGUID, hwndParent, machineNameUTF16, 0)
}

//sys	setupDiGetDeviceInfoListDetail(DeviceInfoSet DevInfo, DeviceInfoSetDetailData *_SP_DEVINFO_LIST_DETAIL_DATA) (err error) = setupapi.SetupDiGetDeviceInfoListDetailW

// SetupDiGetDeviceInfoListDetail function retrieves information associated with a device information set including the class GUID, remote computer handle, and remote computer name.
func SetupDiGetDeviceInfoListDetail(DeviceInfoSet DevInfo) (DeviceInfoSetDetailData *DevInfoListDetailData, err error) {
	var _data _SP_DEVINFO_LIST_DETAIL_DATA
	_data.Size = uint32(unsafe.Sizeof(_data))

	err = setupDiGetDeviceInfoListDetail(DeviceInfoSet, &_data)
	if err != nil {
		return
	}

	return _data.toGo(), nil
}

// GetDeviceInfoListDetail method retrieves information associated with a device information set including the class GUID, remote computer handle, and remote computer name.
func (DeviceInfoSet DevInfo) GetDeviceInfoListDetail() (DeviceInfoSetDetailData *DevInfoListDetailData, err error) {
	return SetupDiGetDeviceInfoListDetail(DeviceInfoSet)
}

//sys	setupDiCreateDeviceInfo(DeviceInfoSet DevInfo, DeviceName *uint16, ClassGUID *windows.GUID, DeviceDescription *uint16, hwndParent uintptr, CreationFlags DICD, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiCreateDeviceInfoW

// SetupDiCreateDeviceInfo function creates a new device information element and adds it as a new member to the specified device information set.
func SetupDiCreateDeviceInfo(DeviceInfoSet DevInfo, DeviceName string, ClassGUID *windows.GUID, DeviceDescription string, hwndParent uintptr, CreationFlags DICD) (DeviceInfoData *SP_DEVINFO_DATA, err error) {
	deviceNameUTF16, err := syscall.UTF16PtrFromString(DeviceName)
	if err != nil {
		return
	}

	var deviceDescriptionUTF16 *uint16
	if DeviceDescription != "" {
		deviceDescriptionUTF16, err = syscall.UTF16PtrFromString(DeviceDescription)
		if err != nil {
			return
		}
	}

	data := SP_DEVINFO_DATA{}
	data.Size = uint32(unsafe.Sizeof(data))

	return &data, setupDiCreateDeviceInfo(DeviceInfoSet, deviceNameUTF16, ClassGUID, deviceDescriptionUTF16, hwndParent, CreationFlags, &data)
}

// CreateDeviceInfo method creates a new device information element and adds it as a new member to the specified device information set.
func (DeviceInfoSet DevInfo) CreateDeviceInfo(DeviceName string, ClassGUID *windows.GUID, DeviceDescription string, hwndParent uintptr, CreationFlags DICD) (DeviceInfoData *SP_DEVINFO_DATA, err error) {
	return SetupDiCreateDeviceInfo(DeviceInfoSet, DeviceName, ClassGUID, DeviceDescription, hwndParent, CreationFlags)
}

//sys	setupDiEnumDeviceInfo(DeviceInfoSet DevInfo, MemberIndex uint32, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiEnumDeviceInfo

// SetupDiEnumDeviceInfo function returns a SP_DEVINFO_DATA structure that specifies a device information element in a device information set.
func SetupDiEnumDeviceInfo(DeviceInfoSet DevInfo, MemberIndex int) (DeviceInfoData *SP_DEVINFO_DATA, err error) {
	data := SP_DEVINFO_DATA{}
	data.Size = uint32(unsafe.Sizeof(data))

	return &data, setupDiEnumDeviceInfo(DeviceInfoSet, uint32(MemberIndex), &data)
}

// EnumDeviceInfo method returns a SP_DEVINFO_DATA structure that specifies a device information element in a device information set.
func (DeviceInfoSet DevInfo) EnumDeviceInfo(MemberIndex int) (DeviceInfoData *SP_DEVINFO_DATA, err error) {
	return SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex)
}

// SetupDiDestroyDeviceInfoList function deletes a device information set and frees all associated memory.
//sys	SetupDiDestroyDeviceInfoList(DeviceInfoSet DevInfo) (err error) = setupapi.SetupDiDestroyDeviceInfoList

// Close method deletes a device information set and frees all associated memory.
func (DeviceInfoSet DevInfo) Close() error {
	return SetupDiDestroyDeviceInfoList(DeviceInfoSet)
}

//sys	setupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator *uint16, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName *uint16, reserved uintptr) (handle DevInfo, err error) [failretval==DevInfo(windows.InvalidHandle)] = setupapi.SetupDiGetClassDevsExW

// SetupDiGetClassDevsEx function returns a handle to a device information set that contains requested device information elements for a local or a remote computer.
func SetupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator string, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName string) (handle DevInfo, err error) {
	var enumeratorUTF16 *uint16
	if Enumerator != "" {
		enumeratorUTF16, err = syscall.UTF16PtrFromString(Enumerator)
		if err != nil {
			return
		}
	}
	var machineNameUTF16 *uint16
	if MachineName != "" {
		machineNameUTF16, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}
	return setupDiGetClassDevsEx(ClassGUID, enumeratorUTF16, hwndParent, Flags, DeviceInfoSet, machineNameUTF16, 0)
}

// SetupDiCallClassInstaller function calls the appropriate class installer, and any registered co-installers, with the specified installation request (DIF code).
//sys	SetupDiCallClassInstaller(InstallFunction DI_FUNCTION, DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiCallClassInstaller

// CallClassInstaller member calls the appropriate class installer, and any registered co-installers, with the specified installation request (DIF code).
func (DeviceInfoSet DevInfo) CallClassInstaller(InstallFunction DI_FUNCTION, DeviceInfoData *SP_DEVINFO_DATA) (err error) {
	return SetupDiCallClassInstaller(InstallFunction, DeviceInfoSet, DeviceInfoData)
}

//sys	setupDiOpenDevRegKey(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key windows.Handle, err error) [failretval==windows.InvalidHandle] = setupapi.SetupDiOpenDevRegKey

// SetupDiOpenDevRegKey function opens a registry key for device-specific configuration information.
func SetupDiOpenDevRegKey(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key registry.Key, err error) {
	handle, err := setupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, samDesired)
	return registry.Key(handle), err
}

// OpenDevRegKey method opens a registry key for device-specific configuration information.
func (DeviceInfoSet DevInfo) OpenDevRegKey(DeviceInfoData *SP_DEVINFO_DATA, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key registry.Key, err error) {
	return SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, Scope, HwProfile, KeyType, samDesired)
}

//sys	setupDiGetDeviceRegistryProperty(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Property SPDRP, PropertyRegDataType *uint32, PropertyBuffer *byte, PropertyBufferSize uint32, RequiredSize *uint32) (err error) = setupapi.SetupDiGetDeviceRegistryPropertyW

// SetupDiGetDeviceRegistryProperty function retrieves a specified Plug and Play device property.
func SetupDiGetDeviceRegistryProperty(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Property SPDRP) (value interface{}, err error) {
	buf := make([]byte, 0x100)
	var dataType, bufLen uint32
	err = setupDiGetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData, Property, &dataType, &buf[0], uint32(cap(buf)), &bufLen)
	if err == nil {
		// The buffer was sufficiently big.
		return getRegistryValue(buf[:bufLen], dataType)
	}

	if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_INSUFFICIENT_BUFFER {
		// The buffer was too small. Now that we got the required size, create another one big enough and retry.
		buf = make([]byte, bufLen)
		err = setupDiGetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData, Property, &dataType, &buf[0], uint32(cap(buf)), &bufLen)
		if err == nil {
			return getRegistryValue(buf[:bufLen], dataType)
		}
	}

	return
}

func getRegistryValue(buf []byte, dataType uint32) (interface{}, error) {
	switch dataType {
	case windows.REG_SZ:
		return windows.UTF16ToString(toUTF16(buf)), nil
	case windows.REG_EXPAND_SZ:
		return registry.ExpandString(windows.UTF16ToString(toUTF16(buf)))
	case windows.REG_BINARY:
		return buf, nil
	case windows.REG_DWORD_LITTLE_ENDIAN:
		return binary.LittleEndian.Uint32(buf), nil
	case windows.REG_DWORD_BIG_ENDIAN:
		return binary.BigEndian.Uint32(buf), nil
	case windows.REG_MULTI_SZ:
		bufW := toUTF16(buf)
		a := []string{}
		for i := 0; i < len(bufW); {
			j := i + wcslen(bufW[i:])
			if i < j {
				a = append(a, windows.UTF16ToString(bufW[i:j]))
			}
			i = j + 1
		}
		return a, nil
	case windows.REG_QWORD_LITTLE_ENDIAN:
		return binary.LittleEndian.Uint64(buf), nil
	default:
		return nil, fmt.Errorf("Unsupported registry value type: %v", dataType)
	}
}

func toUTF16(buf []byte) []uint16 {
	sl := struct {
		addr *uint16
		len  int
		cap  int
	}{(*uint16)(unsafe.Pointer(&buf[0])), len(buf) / 2, cap(buf) / 2}
	return *(*[]uint16)(unsafe.Pointer(&sl))
}

func wcslen(str []uint16) int {
	for i := 0; i < len(str); i++ {
		if str[i] == 0 {
			return i
		}
	}
	return len(str)
}

// GetDeviceRegistryProperty method retrieves a specified Plug and Play device property.
func (DeviceInfoSet DevInfo) GetDeviceRegistryProperty(DeviceInfoData *SP_DEVINFO_DATA, Property SPDRP) (value interface{}, err error) {
	return SetupDiGetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData, Property)
}

//sys	setupDiSetDeviceRegistryProperty(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Property SPDRP, PropertyBuffer *byte, PropertyBufferSize uint32) (err error) = setupapi.SetupDiSetDeviceRegistryPropertyW

// SetupDiSetDeviceRegistryProperty function sets a Plug and Play device property for a device.
func SetupDiSetDeviceRegistryProperty(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, Property SPDRP, PropertyBuffer []byte) (err error) {
	return setupDiSetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData, Property, &PropertyBuffer[0], uint32(len(PropertyBuffer)))
}

// SetDeviceRegistryProperty function sets a Plug and Play device property for a device.
func (DeviceInfoSet DevInfo) SetDeviceRegistryProperty(DeviceInfoData *SP_DEVINFO_DATA, Property SPDRP, PropertyBuffer []byte) (err error) {
	return SetupDiSetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData, Property, PropertyBuffer)
}

//sys	setupDiGetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *_SP_DEVINSTALL_PARAMS) (err error) = setupapi.SetupDiGetDeviceInstallParamsW

// SetupDiGetDeviceInstallParams function retrieves device installation parameters for a device information set or a particular device information element.
func SetupDiGetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA) (DeviceInstallParams *DevInstallParams, err error) {
	var _data _SP_DEVINSTALL_PARAMS
	_data.Size = uint32(unsafe.Sizeof(_data))

	err = setupDiGetDeviceInstallParams(DeviceInfoSet, DeviceInfoData, &_data)
	if err != nil {
		return
	}

	return _data.toGo(), nil
}

// GetDeviceInstallParams method retrieves device installation parameters for a device information set or a particular device information element.
func (DeviceInfoSet DevInfo) GetDeviceInstallParams(DeviceInfoData *SP_DEVINFO_DATA) (DeviceInstallParams *DevInstallParams, err error) {
	return SetupDiGetDeviceInstallParams(DeviceInfoSet, DeviceInfoData)
}

// SetupDiGetClassInstallParams function retrieves class installation parameters for a device information set or a particular device information element.
//sys	SetupDiGetClassInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, ClassInstallParams *SP_CLASSINSTALL_HEADER, ClassInstallParamsSize uint32, RequiredSize *uint32) (err error) = setupapi.SetupDiGetClassInstallParamsW

// GetClassInstallParams method retrieves class installation parameters for a device information set or a particular device information element.
func (DeviceInfoSet DevInfo) GetClassInstallParams(DeviceInfoData *SP_DEVINFO_DATA, ClassInstallParams *SP_CLASSINSTALL_HEADER, ClassInstallParamsSize uint32, RequiredSize *uint32) (err error) {
	return SetupDiGetClassInstallParams(DeviceInfoSet, DeviceInfoData, ClassInstallParams, ClassInstallParamsSize, RequiredSize)
}

//sys	setupDiSetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *_SP_DEVINSTALL_PARAMS) (err error) = setupapi.SetupDiSetDeviceInstallParamsW

// SetupDiSetDeviceInstallParams function sets device installation parameters for a device information set or a particular device information element.
func SetupDiSetDeviceInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *DevInstallParams) (err error) {
	_data, err := DeviceInstallParams.toWindows()
	if err != nil {
		return
	}

	return setupDiSetDeviceInstallParams(DeviceInfoSet, DeviceInfoData, _data)
}

// SetDeviceInstallParams member sets device installation parameters for a device information set or a particular device information element.
func (DeviceInfoSet DevInfo) SetDeviceInstallParams(DeviceInfoData *SP_DEVINFO_DATA, DeviceInstallParams *DevInstallParams) (err error) {
	return SetupDiSetDeviceInstallParams(DeviceInfoSet, DeviceInfoData, DeviceInstallParams)
}

// SetupDiSetClassInstallParams function sets or clears class install parameters for a device information set or a particular device information element.
//sys	SetupDiSetClassInstallParams(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA, ClassInstallParams *SP_CLASSINSTALL_HEADER, ClassInstallParamsSize uint32) (err error) = setupapi.SetupDiSetClassInstallParamsW

// SetClassInstallParams method sets or clears class install parameters for a device information set or a particular device information element.
func (DeviceInfoSet DevInfo) SetClassInstallParams(DeviceInfoData *SP_DEVINFO_DATA, ClassInstallParams *SP_CLASSINSTALL_HEADER, ClassInstallParamsSize uint32) (err error) {
	return SetupDiSetClassInstallParams(DeviceInfoSet, DeviceInfoData, ClassInstallParams, ClassInstallParamsSize)
}

//sys	setupDiClassNameFromGuidEx(ClassGUID *windows.GUID, ClassName *uint16, ClassNameSize uint32, RequiredSize *uint32, MachineName *uint16, Reserved uintptr) (err error) = setupapi.SetupDiClassNameFromGuidExW

// SetupDiClassNameFromGuidEx function retrieves the class name associated with a class GUID. The class can be installed on a local or remote computer.
func SetupDiClassNameFromGuidEx(ClassGUID *windows.GUID, MachineName string) (ClassName string, err error) {
	var classNameUTF16 [MAX_CLASS_NAME_LEN]uint16

	var machineNameUTF16 *uint16
	if MachineName != "" {
		machineNameUTF16, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}

	err = setupDiClassNameFromGuidEx(ClassGUID, &classNameUTF16[0], MAX_CLASS_NAME_LEN, nil, machineNameUTF16, 0)
	if err != nil {
		return
	}

	ClassName = windows.UTF16ToString(classNameUTF16[:])
	return
}

//sys	setupDiClassGuidsFromNameEx(ClassName *uint16, ClassGuidList *windows.GUID, ClassGuidListSize uint32, RequiredSize *uint32, MachineName *uint16, Reserved uintptr) (err error) = setupapi.SetupDiClassGuidsFromNameExW

// SetupDiClassGuidsFromNameEx function retrieves the GUIDs associated with the specified class name. This resulting list contains the classes currently installed on a local or remote computer.
func SetupDiClassGuidsFromNameEx(ClassName string, MachineName string) (ClassGuidList []windows.GUID, err error) {
	classNameUTF16, err := syscall.UTF16PtrFromString(ClassName)
	if err != nil {
		return
	}

	const bufCapacity = 4
	var buf [bufCapacity]windows.GUID
	var bufLen uint32

	var machineNameUTF16 *uint16
	if MachineName != "" {
		machineNameUTF16, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}

	err = setupDiClassGuidsFromNameEx(classNameUTF16, &buf[0], bufCapacity, &bufLen, machineNameUTF16, 0)
	if err == nil {
		// The GUID array was sufficiently big. Return its slice.
		return buf[:bufLen], nil
	}

	if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_INSUFFICIENT_BUFFER {
		// The GUID array was too small. Now that we got the required size, create another one big enough and retry.
		buf := make([]windows.GUID, bufLen)
		err = setupDiClassGuidsFromNameEx(classNameUTF16, &buf[0], bufLen, &bufLen, machineNameUTF16, 0)
		if err == nil {
			return buf[:bufLen], nil
		}
	}

	return
}

//sys	setupDiGetSelectedDevice(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiGetSelectedDevice

// SetupDiGetSelectedDevice function retrieves the selected device information element in a device information set.
func SetupDiGetSelectedDevice(DeviceInfoSet DevInfo) (DeviceInfoData *SP_DEVINFO_DATA, err error) {
	data := SP_DEVINFO_DATA{}
	data.Size = uint32(unsafe.Sizeof(data))

	return &data, setupDiGetSelectedDevice(DeviceInfoSet, &data)
}

// GetSelectedDevice method retrieves the selected device information element in a device information set.
func (DeviceInfoSet DevInfo) GetSelectedDevice() (DeviceInfoData *SP_DEVINFO_DATA, err error) {
	return SetupDiGetSelectedDevice(DeviceInfoSet)
}

// SetupDiSetSelectedDevice function sets a device information element as the selected member of a device information set. This function is typically used by an installation wizard.
//sys	SetupDiSetSelectedDevice(DeviceInfoSet DevInfo, DeviceInfoData *SP_DEVINFO_DATA) (err error) = setupapi.SetupDiSetSelectedDevice

// SetSelectedDevice method sets a device information element as the selected member of a device information set. This function is typically used by an installation wizard.
func (DeviceInfoSet DevInfo) SetSelectedDevice(DeviceInfoData *SP_DEVINFO_DATA) (err error) {
	return SetupDiSetSelectedDevice(DeviceInfoSet, DeviceInfoData)
}
