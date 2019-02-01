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

var guidDeviceClassNet = windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var computerName string

func init() {
	computerName, _ = windows.ComputerName()
}

func TestSetupDiGetClassDevsEx(t *testing.T) {
	dev_info_list, err := SetupDiGetClassDevsEx(&guidDeviceClassNet, "PCI", 0, DIGCF_PRESENT, DevInfo(0), computerName)
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

func TestSetupDiGetDeviceInfoListDetailLocal(t *testing.T) {
	dev_info_list, err := SetupDiGetClassDevsEx(&guidDeviceClassNet, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer SetupDiDestroyDeviceInfoList(dev_info_list)

	data, err := SetupDiGetDeviceInfoListDetail(dev_info_list)
	if err != nil {
		t.Errorf("Error calling SetupDiGetDeviceInfoListDetail: %s", err.Error())
	}

	if data.ClassGUID != guidDeviceClassNet {
		t.Error("SetupDiGetDeviceInfoListDetail returned different class GUID")
	}

	if data.RemoteMachineHandle != windows.Handle(0) {
		t.Error("SetupDiGetDeviceInfoListDetail returned non-NULL remote machine handle")
	}

	if data.RemoteMachineName != "" {
		t.Error("SetupDiGetDeviceInfoListDetail returned non-NULL remote machine name")
	}
}

func TestSetupDiGetDeviceInfoListDetailRemote(t *testing.T) {
	dev_info_list, err := SetupDiGetClassDevsEx(&guidDeviceClassNet, "", 0, DIGCF_PRESENT, DevInfo(0), computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer SetupDiDestroyDeviceInfoList(dev_info_list)

	data, err := SetupDiGetDeviceInfoListDetail(dev_info_list)
	if err != nil {
		t.Errorf("Error calling SetupDiGetDeviceInfoListDetail: %s", err.Error())
	}

	if data.ClassGUID != guidDeviceClassNet {
		t.Error("SetupDiGetDeviceInfoListDetail returned different class GUID")
	}

	if data.RemoteMachineHandle == windows.Handle(0) {
		t.Error("SetupDiGetDeviceInfoListDetail returned NULL remote machine handle")
	}

	if data.RemoteMachineName != computerName {
		t.Error("SetupDiGetDeviceInfoListDetail returned different remote machine name")
	}
}
