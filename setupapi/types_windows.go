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

// SP_DEVINFO_LIST_DETAIL_DATA is a structure for detailed information on a device information set (used for SetupDiGetDeviceInfoListDetail which supercedes the functionality of SetupDiGetDeviceInfoListClass).
type SP_DEVINFO_LIST_DETAIL_DATA struct {
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
