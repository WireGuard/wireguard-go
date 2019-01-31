/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"golang.org/x/sys/windows"
)

const (
	SP_MAX_MACHINENAME_LENGTH = windows.MAX_PATH + 3
)

type DIGCF uint32

const (
	Default         DIGCF = 0x00000001
	Present         DIGCF = 0x00000002
	AllClasses      DIGCF = 0x00000004
	Profile         DIGCF = 0x00000008
	DeviceInterface DIGCF = 0x00000010
	InterfaceDevice DIGCF = 0x00000010
)

type DevInfo windows.Handle

//sys	setupDiGetClassDevsEx(ClassGuid *windows.GUID, Enumerator *string, hwndParent uintptr, Flags uint32, DeviceInfoSet uintptr, MachineName string, reserved uint32) (handle windows.Handle, err error) = setupapi.SetupDiGetClassDevsExW

// The SetupDiGetClassDevsEx function returns a handle to a device information set that contains requested device information elements for a local or a remote computer.
func SetupDiGetClassDevsEx(ClassGuid *windows.GUID, Enumerator string, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName string) (DevInfo, error) {
	enumerator := &Enumerator

	if Enumerator == "" {
		enumerator = nil
	}

	h, err := setupDiGetClassDevsEx(ClassGuid, enumerator, hwndParent, uint32(Flags), uintptr(DeviceInfoSet), MachineName, 0)
	return DevInfo(h), err
}
