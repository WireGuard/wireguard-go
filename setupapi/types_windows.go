/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"golang.org/x/sys/windows"
)

// DIGCF flags controll what is included in the device information set built by SetupDiGetClassDevs
type DIGCF uint32

const (
	DIGCF_DEFAULT         DIGCF = 0x00000001 // only valid with DIGCF_DEVICEINTERFACE
	DIGCF_PRESENT         DIGCF = 0x00000002
	DIGCF_ALLCLASSES      DIGCF = 0x00000004
	DIGCF_PROFILE         DIGCF = 0x00000008
	DIGCF_DEVICEINTERFACE DIGCF = 0x00000010
)

// DevInfo holds reference to device information set
type DevInfo windows.Handle

// Close function deletes a device information set and frees all associated memory.
func (h DevInfo) Close() error {
	if h != DevInfo(windows.InvalidHandle) {
		return SetupDiDestroyDeviceInfoList(h)
	}

	return nil
}

const (
	// SP_MAX_MACHINENAME_LENGTH defines maximum length of a machine name in the format expected by ConfigMgr32 CM_Connect_Machine (i.e., "\\\\MachineName\0").
	SP_MAX_MACHINENAME_LENGTH = windows.MAX_PATH + 3
)

type _SP_DEVINFO_LIST_DETAIL_DATA struct {
	Size                uint32
	ClassGUID           windows.GUID
	RemoteMachineHandle windows.Handle
	RemoteMachineName   [SP_MAX_MACHINENAME_LENGTH]uint16
}

// DevInfoListDetailData is a structure for detailed information on a device information set (used for SetupDiGetDeviceInfoListDetail which supercedes the functionality of SetupDiGetDeviceInfoListClass).
type DevInfoListDetailData struct {
	ClassGUID           windows.GUID
	RemoteMachineHandle windows.Handle
	RemoteMachineName   string
}

// SP_DEVINFO_DATA is a device information structure (references a device instance that is a member of a device information set)
type SP_DEVINFO_DATA struct {
	Size      uint32
	ClassGUID windows.GUID
	DevInst   uint32 // DEVINST handle
	_         uintptr
}

// DICS_FLAG specifies the scope of a device property change
type DICS_FLAG uint32

const (
	DICS_FLAG_GLOBAL         DICS_FLAG = 0x00000001 // make change in all hardware profiles
	DICS_FLAG_CONFIGSPECIFIC DICS_FLAG = 0x00000002 // make change in specified profile only
	DICS_FLAG_CONFIGGENERAL  DICS_FLAG = 0x00000004 // 1 or more hardware profile-specific changes to follow
)

// DIREG specifies values for SetupDiCreateDevRegKey, SetupDiOpenDevRegKey, and SetupDiDeleteDevRegKey.
type DIREG uint32

const (
	DIREG_DEV  DIREG = 0x00000001 // Open/Create/Delete device key
	DIREG_DRV  DIREG = 0x00000002 // Open/Create/Delete driver key
	DIREG_BOTH DIREG = 0x00000004 // Delete both driver and Device key
)
