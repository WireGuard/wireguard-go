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

var deviceClassNetGUID = windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var computerName string

func init() {
	computerName, _ = windows.ComputerName()
}

func TestSetupDiGetClassDevsEx(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "PCI", 0, DIGCF_PRESENT, DevInfo(0), computerName)
	if err == nil {
		devInfoList.Close()
	} else {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}

	devInfoList, err = SetupDiGetClassDevsEx(nil, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err == nil {
		devInfoList.Close()
		t.Errorf("SetupDiGetClassDevsEx(nil, ...) should fail")
	} else {
		if errWin, ok := err.(syscall.Errno); !ok || errWin != 87 /*ERROR_INVALID_PARAMETER*/ {
			t.Errorf("SetupDiGetClassDevsEx(nil, ...) should fail with ERROR_INVALID_PARAMETER")
		}
	}
}

func TestSetupDiGetDeviceInfoListDetailLocal(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	data, err := SetupDiGetDeviceInfoListDetail(devInfoList)
	if err != nil {
		t.Errorf("Error calling SetupDiGetDeviceInfoListDetail: %s", err.Error())
	}

	if data.ClassGUID != deviceClassNetGUID {
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
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	data, err := SetupDiGetDeviceInfoListDetail(devInfoList)
	if err != nil {
		t.Errorf("Error calling SetupDiGetDeviceInfoListDetail: %s", err.Error())
	}

	if data.ClassGUID != deviceClassNetGUID {
		t.Error("SetupDiGetDeviceInfoListDetail returned different class GUID")
	}

	if data.RemoteMachineHandle == windows.Handle(0) {
		t.Error("SetupDiGetDeviceInfoListDetail returned NULL remote machine handle")
	}

	if data.RemoteMachineName != computerName {
		t.Error("SetupDiGetDeviceInfoListDetail returned different remote machine name")
	}
}

func TestSetupDiEnumDeviceInfo(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	var data SP_DEVINFO_DATA
	for i := 0; true; i++ {
		err := SetupDiEnumDeviceInfo(devInfoList, i, &data)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		if data.ClassGUID != deviceClassNetGUID {
			t.Error("SetupDiEnumDeviceInfo returned different class GUID")
		}
	}
}

func TestSetupDiOpenDevRegKey(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	var data SP_DEVINFO_DATA
	for i := 0; true; i++ {
		err := SetupDiEnumDeviceInfo(devInfoList, i, &data)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		key, err := SetupDiOpenDevRegKey(devInfoList, &data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, windows.KEY_READ)
		if err != nil {
			t.Errorf("Error calling SetupDiOpenDevRegKey: %s", err.Error())
		}
		defer key.Close()
	}
}

func TestSetupDiGetDeviceInstallParams(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	var data SP_DEVINFO_DATA
	for i := 0; true; i++ {
		err := SetupDiEnumDeviceInfo(devInfoList, i, &data)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		_, err = SetupDiGetDeviceInstallParams(devInfoList, &data)
		if err != nil {
			t.Errorf("Error calling SetupDiOpenDevRegKey: %s", err.Error())
		}
	}
}
