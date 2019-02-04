/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

var deviceClassNetGUID = windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var computerName string

func init() {
	computerName, _ = windows.ComputerName()
}

func TestSetupDiClassNameFromGuidEx(t *testing.T) {
	deviceClassNetName, err := SetupDiClassNameFromGuidEx(&deviceClassNetGUID, "")
	if err != nil {
		t.Errorf("Error calling SetupDiClassNameFromGuidEx: %s", err.Error())
	} else if strings.ToLower(deviceClassNetName) != "net" {
		t.Errorf("SetupDiClassNameFromGuidEx(%x) should return \"Net\"", deviceClassNetGUID)
	}

	deviceClassNetName, err = SetupDiClassNameFromGuidEx(&deviceClassNetGUID, computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiClassNameFromGuidEx: %s", err.Error())
	} else if strings.ToLower(deviceClassNetName) != "net" {
		t.Errorf("SetupDiClassNameFromGuidEx(%x) should return \"Net\"", deviceClassNetGUID)
	}

	_, err = SetupDiClassNameFromGuidEx(nil, "")
	if err == nil {
		t.Errorf("SetupDiClassNameFromGuidEx(nil) should fail")
	} else {
		if errWin, ok := err.(syscall.Errno); !ok || errWin != 1784 /*ERROR_INVALID_USER_BUFFER*/ {
			t.Errorf("SetupDiClassNameFromGuidEx(nil) should fail with ERROR_INVALID_USER_BUFFER")
		}
	}
}

func TestSetupDiClassGuidsFromNameEx(t *testing.T) {
	ClassGUIDs, err := SetupDiClassGuidsFromNameEx("Net", "")
	if err != nil {
		t.Errorf("Error calling SetupDiClassGuidsFromNameEx: %s", err.Error())
	} else {
		found := false
		for i := range ClassGUIDs {
			if ClassGUIDs[i] == deviceClassNetGUID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SetupDiClassGuidsFromNameEx(\"Net\") should return %x", deviceClassNetGUID)
		}
	}

	ClassGUIDs, err = SetupDiClassGuidsFromNameEx("foobar-34274a51-a6e6-45f0-80d6-c62be96dd5fe", computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiClassGuidsFromNameEx: %s", err.Error())
	} else if len(ClassGUIDs) != 0 {
		t.Errorf("SetupDiClassGuidsFromNameEx(\"foobar-34274a51-a6e6-45f0-80d6-c62be96dd5fe\") should return an empty GUID set")
	}
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
	} else {
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
	} else {
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
}

func TestSetupDiEnumDeviceInfo(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		data, err := SetupDiEnumDeviceInfo(devInfoList, i)
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

	for i := 0; true; i++ {
		data, err := SetupDiEnumDeviceInfo(devInfoList, i)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		key, err := SetupDiOpenDevRegKey(devInfoList, data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, windows.KEY_READ)
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

	for i := 0; true; i++ {
		data, err := SetupDiEnumDeviceInfo(devInfoList, i)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		_, err = SetupDiGetDeviceInstallParams(devInfoList, data)
		if err != nil {
			t.Errorf("Error calling SetupDiOpenDevRegKey: %s", err.Error())
		}
	}
}
