/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

var deviceClassNetGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var computerName string

func init() {
	computerName, _ = windows.ComputerName()
}

func TestSetupDiCreateDeviceInfoListEx(t *testing.T) {
	devInfoList, err := SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, 0, "")
	if err != nil {
		t.Errorf("Error calling SetupDiCreateDeviceInfoListEx: %s", err.Error())
	} else {
		devInfoList.Close()
	}

	devInfoList, err = SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, 0, computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiCreateDeviceInfoListEx: %s", err.Error())
	} else {
		devInfoList.Close()
	}

	devInfoList, err = SetupDiCreateDeviceInfoListEx(nil, 0, "")
	if err != nil {
		t.Errorf("Error calling SetupDiCreateDeviceInfoListEx(nil): %s", err.Error())
	} else {
		devInfoList.Close()
	}
}

func TestSetupDiGetDeviceInfoListDetail(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	data, err := devInfoList.DeviceInfoListDetail()
	if err != nil {
		t.Errorf("Error calling SetupDiGetDeviceInfoListDetail: %s", err.Error())
	} else {
		if data.ClassGUID != deviceClassNetGUID {
			t.Error("SetupDiGetDeviceInfoListDetail returned different class GUID")
		}

		if data.RemoteMachineHandle != windows.Handle(0) {
			t.Error("SetupDiGetDeviceInfoListDetail returned non-NULL remote machine handle")
		}

		if data.RemoteMachineName() != "" {
			t.Error("SetupDiGetDeviceInfoListDetail returned non-NULL remote machine name")
		}
	}

	devInfoList, err = SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	data, err = devInfoList.DeviceInfoListDetail()
	if err != nil {
		t.Errorf("Error calling SetupDiGetDeviceInfoListDetail: %s", err.Error())
	} else {
		if data.ClassGUID != deviceClassNetGUID {
			t.Error("SetupDiGetDeviceInfoListDetail returned different class GUID")
		}

		if data.RemoteMachineHandle == windows.Handle(0) {
			t.Error("SetupDiGetDeviceInfoListDetail returned NULL remote machine handle")
		}

		if data.RemoteMachineName() != computerName {
			t.Error("SetupDiGetDeviceInfoListDetail returned different remote machine name")
		}
	}

	data = &DevInfoListDetailData{}
	data.SetRemoteMachineName("foobar")
	if data.RemoteMachineName() != "foobar" {
		t.Error("DevInfoListDetailData.(Get|Set)RemoteMachineName() differ")
	}
}

func TestSetupDiCreateDeviceInfo(t *testing.T) {
	devInfoList, err := SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, 0, computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiCreateDeviceInfoListEx: %s", err.Error())
	}
	defer devInfoList.Close()

	deviceClassNetName, err := SetupDiClassNameFromGuidEx(&deviceClassNetGUID, computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiClassNameFromGuidEx: %s", err.Error())
	}

	devInfoData, err := devInfoList.CreateDeviceInfo(deviceClassNetName, &deviceClassNetGUID, "This is a test device", 0, DICD_GENERATE_ID)
	if err != nil {
		// Access denied is expected, as the SetupDiCreateDeviceInfo() require elevation to succeed.
		if errWin, ok := err.(windows.Errno); !ok || errWin != windows.ERROR_ACCESS_DENIED {
			t.Errorf("Error calling SetupDiCreateDeviceInfo: %s", err.Error())
		}
	} else if devInfoData.ClassGUID != deviceClassNetGUID {
		t.Error("SetupDiCreateDeviceInfo returned different class GUID")
	}
}

func TestSetupDiEnumDeviceInfo(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		data, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		if data.ClassGUID != deviceClassNetGUID {
			t.Error("SetupDiEnumDeviceInfo returned different class GUID")
		}

		_, err = devInfoList.DeviceInstanceID(data)
		if err != nil {
			t.Errorf("Error calling SetupDiGetDeviceInstanceId: %s", err.Error())
		}
	}
}

func TestDevInfo_BuildDriverInfoList(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		deviceData, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		const driverType SPDIT = SPDIT_COMPATDRIVER
		err = devInfoList.BuildDriverInfoList(deviceData, driverType)
		if err != nil {
			t.Errorf("Error calling SetupDiBuildDriverInfoList: %s", err.Error())
		}
		defer devInfoList.DestroyDriverInfoList(deviceData, driverType)

		var selectedDriverData *DrvInfoData
		for j := 0; true; j++ {
			driverData, err := devInfoList.EnumDriverInfo(deviceData, driverType, j)
			if err != nil {
				if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
					break
				}
				continue
			}

			if driverData.DriverType == 0 {
				continue
			}

			if !driverData.IsNewer(windows.Filetime{}, 0) {
				t.Error("Driver should have non-zero date and version")
			}
			if !driverData.IsNewer(windows.Filetime{HighDateTime: driverData.DriverDate.HighDateTime}, 0) {
				t.Error("Driver should have non-zero date and version")
			}
			if driverData.IsNewer(windows.Filetime{HighDateTime: driverData.DriverDate.HighDateTime + 1}, 0) {
				t.Error("Driver should report newer version on high-date-time")
			}
			if !driverData.IsNewer(windows.Filetime{HighDateTime: driverData.DriverDate.HighDateTime, LowDateTime: driverData.DriverDate.LowDateTime}, 0) {
				t.Error("Driver should have non-zero version")
			}
			if driverData.IsNewer(windows.Filetime{HighDateTime: driverData.DriverDate.HighDateTime, LowDateTime: driverData.DriverDate.LowDateTime + 1}, 0) {
				t.Error("Driver should report newer version on low-date-time")
			}
			if driverData.IsNewer(windows.Filetime{HighDateTime: driverData.DriverDate.HighDateTime, LowDateTime: driverData.DriverDate.LowDateTime}, driverData.DriverVersion) {
				t.Error("Driver should not be newer than itself")
			}
			if driverData.IsNewer(windows.Filetime{HighDateTime: driverData.DriverDate.HighDateTime, LowDateTime: driverData.DriverDate.LowDateTime}, driverData.DriverVersion+1) {
				t.Error("Driver should report newer version on version")
			}

			err = devInfoList.SetSelectedDriver(deviceData, driverData)
			if err != nil {
				t.Errorf("Error calling SetupDiSetSelectedDriver: %s", err.Error())
			} else {
				selectedDriverData = driverData
			}

			driverDetailData, err := devInfoList.DriverInfoDetail(deviceData, driverData)
			if err != nil {
				t.Errorf("Error calling SetupDiGetDriverInfoDetail: %s", err.Error())
			}

			if driverDetailData.IsCompatible("foobar-aab6e3a4-144e-4786-88d3-6cec361e1edd") {
				t.Error("Invalid HWID compatibitlity reported")
			}
			if !driverDetailData.IsCompatible(strings.ToUpper(driverDetailData.HardwareID())) {
				t.Error("HWID compatibitlity missed")
			}
			a := driverDetailData.CompatIDs()
			for k := range a {
				if !driverDetailData.IsCompatible(strings.ToUpper(a[k])) {
					t.Error("HWID compatibitlity missed")
				}
			}
		}

		selectedDriverData2, err := devInfoList.SelectedDriver(deviceData)
		if err != nil {
			t.Errorf("Error calling SetupDiGetSelectedDriver: %s", err.Error())
		} else if *selectedDriverData != *selectedDriverData2 {
			t.Error("SetupDiGetSelectedDriver should return driver selected with SetupDiSetSelectedDriver")
		}
	}

	data := &DrvInfoData{}
	data.SetDescription("foobar")
	if data.Description() != "foobar" {
		t.Error("DrvInfoData.(Get|Set)Description() differ")
	}
	data.SetMfgName("foobar")
	if data.MfgName() != "foobar" {
		t.Error("DrvInfoData.(Get|Set)MfgName() differ")
	}
	data.SetProviderName("foobar")
	if data.ProviderName() != "foobar" {
		t.Error("DrvInfoData.(Get|Set)ProviderName() differ")
	}
}

func TestSetupDiGetClassDevsEx(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "PCI", 0, DIGCF_PRESENT, DevInfo(0), computerName)
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	} else {
		devInfoList.Close()
	}

	devInfoList, err = SetupDiGetClassDevsEx(nil, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		if errWin, ok := err.(windows.Errno); !ok || errWin != windows.ERROR_INVALID_PARAMETER {
			t.Errorf("SetupDiGetClassDevsEx(nil, ...) should fail with ERROR_INVALID_PARAMETER")
		}
	} else {
		devInfoList.Close()
		t.Errorf("SetupDiGetClassDevsEx(nil, ...) should fail")
	}
}

func TestSetupDiOpenDevRegKey(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		data, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		key, err := devInfoList.OpenDevRegKey(data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, windows.KEY_READ)
		if err != nil {
			t.Errorf("Error calling SetupDiOpenDevRegKey: %s", err.Error())
		}
		defer key.Close()
	}
}

func TestSetupDiGetDeviceRegistryProperty(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		data, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		val, err := devInfoList.DeviceRegistryProperty(data, SPDRP_CLASS)
		if err != nil {
			t.Errorf("Error calling SetupDiGetDeviceRegistryProperty(SPDRP_CLASS): %s", err.Error())
		} else if class, ok := val.(string); !ok || strings.ToLower(class) != "net" {
			t.Errorf("SetupDiGetDeviceRegistryProperty(SPDRP_CLASS) should return \"Net\"")
		}

		val, err = devInfoList.DeviceRegistryProperty(data, SPDRP_CLASSGUID)
		if err != nil {
			t.Errorf("Error calling SetupDiGetDeviceRegistryProperty(SPDRP_CLASSGUID): %s", err.Error())
		} else if valStr, ok := val.(string); !ok {
			t.Errorf("SetupDiGetDeviceRegistryProperty(SPDRP_CLASSGUID) should return string")
		} else {
			classGUID, err := windows.GUIDFromString(valStr)
			if err != nil {
				t.Errorf("Error parsing GUID returned by SetupDiGetDeviceRegistryProperty(SPDRP_CLASSGUID): %s", err.Error())
			} else if classGUID != deviceClassNetGUID {
				t.Errorf("SetupDiGetDeviceRegistryProperty(SPDRP_CLASSGUID) should return %x", deviceClassNetGUID)
			}
		}

		val, err = devInfoList.DeviceRegistryProperty(data, SPDRP_COMPATIBLEIDS)
		if err != nil {
			// Some devices have no SPDRP_COMPATIBLEIDS.
			if errWin, ok := err.(windows.Errno); !ok || errWin != windows.ERROR_INVALID_DATA {
				t.Errorf("Error calling SetupDiGetDeviceRegistryProperty(SPDRP_COMPATIBLEIDS): %s", err.Error())
			}
		}

		val, err = devInfoList.DeviceRegistryProperty(data, SPDRP_CONFIGFLAGS)
		if err != nil {
			t.Errorf("Error calling SetupDiGetDeviceRegistryProperty(SPDRP_CONFIGFLAGS): %s", err.Error())
		}

		val, err = devInfoList.DeviceRegistryProperty(data, SPDRP_DEVICE_POWER_DATA)
		if err != nil {
			t.Errorf("Error calling SetupDiGetDeviceRegistryProperty(SPDRP_DEVICE_POWER_DATA): %s", err.Error())
		}
	}
}

func TestSetupDiGetDeviceInstallParams(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		data, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		_, err = devInfoList.DeviceInstallParams(data)
		if err != nil {
			t.Errorf("Error calling SetupDiGetDeviceInstallParams: %s", err.Error())
		}
	}

	params := &DevInstallParams{}
	params.SetDriverPath("foobar")
	if params.DriverPath() != "foobar" {
		t.Error("DevInstallParams.(Get|Set)DriverPath() differ")
	}
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
	if err != nil {
		if errWin, ok := err.(windows.Errno); !ok || errWin != windows.ERROR_INVALID_USER_BUFFER {
			t.Errorf("SetupDiClassNameFromGuidEx(nil) should fail with ERROR_INVALID_USER_BUFFER")
		}
	} else {
		t.Errorf("SetupDiClassNameFromGuidEx(nil) should fail")
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

func TestSetupDiGetSelectedDevice(t *testing.T) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		t.Errorf("Error calling SetupDiGetClassDevsEx: %s", err.Error())
	}
	defer devInfoList.Close()

	for i := 0; true; i++ {
		data, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		err = devInfoList.SetSelectedDevice(data)
		if err != nil {
			t.Errorf("Error calling SetupDiSetSelectedDevice: %s", err.Error())
		}

		data2, err := devInfoList.SelectedDevice()
		if err != nil {
			t.Errorf("Error calling SetupDiGetSelectedDevice: %s", err.Error())
		} else if *data != *data2 {
			t.Error("SetupDiGetSelectedDevice returned different data than was set by SetupDiSetSelectedDevice")
		}
	}

	err = devInfoList.SetSelectedDevice(nil)
	if err != nil {
		if errWin, ok := err.(windows.Errno); !ok || errWin != windows.ERROR_INVALID_PARAMETER {
			t.Errorf("SetupDiSetSelectedDevice(nil) should fail with ERROR_INVALID_USER_BUFFER")
		}
	} else {
		t.Errorf("SetupDiSetSelectedDevice(nil) should fail")
	}
}

func TestUTF16ToBuf(t *testing.T) {
	buf := []uint16{0x0123, 0x4567, 0x89ab, 0xcdef}
	buf2 := utf16ToBuf(buf)
	if len(buf)*2 != len(buf2) ||
		cap(buf)*2 != cap(buf2) ||
		buf2[0] != 0x23 || buf2[1] != 0x01 ||
		buf2[2] != 0x67 || buf2[3] != 0x45 ||
		buf2[4] != 0xab || buf2[5] != 0x89 ||
		buf2[6] != 0xef || buf2[7] != 0xcd {
		t.Errorf("SetupDiSetSelectedDevice(nil) should fail with ERROR_INVALID_USER_BUFFER")
	}
	runtime.KeepAlive(buf)
}
