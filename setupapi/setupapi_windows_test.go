/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetupDiGetClassDevsEx(t *testing.T) {
	guidDeviceClassNet := windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

	compName, err := windows.ComputerName()
	if err != nil {
		t.Errorf("Error getting computer name: %s", err.Error())
	}

	dev_info_list, err := SetupDiGetClassDevsEx(&guidDeviceClassNet, "PCI", 0, DIGCF_PRESENT, DevInfo(0), compName)
	if err == nil {
		dev_info_list.Close()
	} else {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}

	dev_info_list, err = SetupDiGetClassDevsEx(nil, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err == nil {
		dev_info_list.Close()
		t.Errorf("SetupDiGetClassDevsEx(nil, ...) should fail")
	} else {
		if errWin, ok := err.(syscall.Errno); !ok || errWin != 87 /*ERROR_INVALID_PARAMETER*/ {
			t.Errorf("SetupDiGetClassDevsEx(nil, ...) should fail with ERROR_INVALID_PARAMETER")
		}
	}
}
