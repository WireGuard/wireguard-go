/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/tun/wintun/guid"
	"golang.zx2c4.com/wireguard/tun/wintun/setupapi"
)

//
// Wintun is a handle of a Wintun adapter
//
type Wintun struct {
	CfgInstanceID windows.GUID
	LUIDIndex     uint32
	IfType        uint32
}

var deviceClassNetGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

const hardwareID = "Wintun"
const enumerator = ""
const machineName = ""

//
// MakeWintun creates interface handle and populates it from device registry key
//
func MakeWintun(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) (*Wintun, error) {
	// Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key.
	key, err := deviceInfoSet.OpenDevRegKey(deviceInfoData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.READ)
	if err != nil {
		return nil, errors.New("Device-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	var valueStr string
	var valueType uint32

	//TODO: Figure out a way to not need to loop like this.
	for i := 0; i < 30; i++ {
		// Read the NetCfgInstanceId value.
		valueStr, valueType, err = key.GetStringValue("NetCfgInstanceId")
		if err != nil {
			time.Sleep(time.Millisecond * 100)
			continue
		}
		if valueType != registry.SZ {
			return nil, fmt.Errorf("NetCfgInstanceId registry value is not REG_SZ (expected: %v, provided: %v)", registry.SZ, valueType)
		}
		break
	}
	if err != nil {
		return nil, errors.New("RegQueryStringValue(\"NetCfgInstanceId\") failed: " + err.Error())
	}

	// Convert to windows.GUID.
	ifid, err := guid.FromString(valueStr)
	if err != nil {
		return nil, fmt.Errorf("NetCfgInstanceId registry value is not a GUID (expected: \"{...}\", provided: %q)", valueStr)
	}

	// Read the NetLuidIndex value.
	luidIdx, valueType, err := key.GetIntegerValue("NetLuidIndex")
	if err != nil {
		return nil, errors.New("RegQueryValue(\"NetLuidIndex\") failed: " + err.Error())
	}

	// Read the NetLuidIndex value.
	ifType, valueType, err := key.GetIntegerValue("*IfType")
	if err != nil {
		return nil, errors.New("RegQueryValue(\"*IfType\") failed: " + err.Error())
	}

	return &Wintun{
		CfgInstanceID: *ifid,
		LUIDIndex:     uint32(luidIdx),
		IfType:        uint32(ifType),
	}, nil
}

//
// GetInterface finds interface by name.
//
// hwndParent is a handle to the top-level window to use for any user
// interface that is related to non-device-specific actions (such as a select-
// device dialog box that uses the global class driver list). This handle is
// optional and can be 0. If a specific top-level window is not required, set
// hwndParent to 0.
//
// Function returns interface if found, or nil otherwise. If the interface is
// found but not Wintun-class, the function returns interface and an error.
//
func GetInterface(ifname string, hwndParent uintptr) (*Wintun, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, enumerator, hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), machineName)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("SetupDiGetClassDevsEx(%v) failed: ", guid.ToString(&deviceClassNetGUID)) + err.Error())
	}
	defer devInfoList.Close()

	// Windows requires each interface to have a different name. When
	// enforcing this, Windows treats interface names case-insensitive. If an
	// interface "FooBar" exists and this function reports there is no
	// interface "foobar", an attempt to create a new interface and name it
	// "foobar" would cause conflict with "FooBar".
	ifname = strings.ToLower(ifname)

	// Iterate.
	for index := 0; ; index++ {
		// Get the device from the list. Should anything be wrong with this device, continue with next.
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		// Get interface ID.
		wintun, err := MakeWintun(devInfoList, deviceData)
		if err != nil {
			continue
		}

		// Get interface name.
		ifname2, err := wintun.GetInterfaceName()
		if err != nil {
			continue
		}

		if ifname == strings.ToLower(ifname2) {
			// Interface name found. Check its driver.
			const driverType = setupapi.SPDIT_COMPATDRIVER
			err = devInfoList.BuildDriverInfoList(deviceData, driverType)
			if err != nil {
				return nil, errors.New("SetupDiBuildDriverInfoList failed: " + err.Error())
			}
			defer devInfoList.DestroyDriverInfoList(deviceData, driverType)

			for index := 0; ; index++ {
				// Get a driver from the list.
				driverData, err := devInfoList.EnumDriverInfo(deviceData, driverType, index)
				if err != nil {
					if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
						break
					}
					// Something is wrong with this driver. Skip it.
					continue
				}

				// Get driver info details.
				driverDetailData, err := devInfoList.GetDriverInfoDetail(deviceData, driverData)
				if err != nil {
					// Something is wrong with this driver. Skip it.
					continue
				}

				if driverDetailData.IsCompatible(hardwareID) {
					// Matching hardware ID found.
					return wintun, nil
				}
			}

			// This interface is not using Wintun driver.
			return wintun, errors.New("Foreign network interface with the same name exists")
		}
	}

	return nil, nil
}

//
// CreateInterface creates a TUN interface.
//
// description is a string that supplies the text description of the device.
// description is optional and can be "".
//
// hwndParent is a handle to the top-level window to use for any user
// interface that is related to non-device-specific actions (such as a select-
// device dialog box that uses the global class driver list). This handle is
// optional and can be 0. If a specific top-level window is not required, set
// hwndParent to 0.
//
// Function returns the network interface ID and a flag if reboot is required.
//
func CreateInterface(description string, hwndParent uintptr) (*Wintun, bool, error) {
	// Create an empty device info set for network adapter device class.
	devInfoList, err := setupapi.SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, hwndParent, machineName)
	if err != nil {
		return nil, false, errors.New(fmt.Sprintf("SetupDiCreateDeviceInfoListEx(%v) failed: ", guid.ToString(&deviceClassNetGUID)) + err.Error())
	}

	// Get the device class name from GUID.
	className, err := setupapi.SetupDiClassNameFromGuidEx(&deviceClassNetGUID, machineName)
	if err != nil {
		return nil, false, errors.New(fmt.Sprintf("SetupDiClassNameFromGuidEx(%v) failed: ", guid.ToString(&deviceClassNetGUID)) + err.Error())
	}

	// Create a new device info element and add it to the device info set.
	deviceData, err := devInfoList.CreateDeviceInfo(className, &deviceClassNetGUID, description, hwndParent, setupapi.DICD_GENERATE_ID)
	if err != nil {
		return nil, false, errors.New("SetupDiCreateDeviceInfo failed: " + err.Error())
	}

	// Set a device information element as the selected member of a device information set.
	err = devInfoList.SetSelectedDevice(deviceData)
	if err != nil {
		return nil, false, errors.New("SetupDiSetSelectedDevice failed: " + err.Error())
	}

	// Set Plug&Play device hardware ID property.
	hwid, err := syscall.UTF16FromString(hardwareID)
	if err != nil {
		return nil, false, err // syscall.UTF16FromString(hardwareID) should never fail: hardwareID is const string without NUL chars.
	}
	err = devInfoList.SetDeviceRegistryProperty(deviceData, setupapi.SPDRP_HARDWAREID, setupapi.UTF16ToBuf(append(hwid, 0)))
	if err != nil {
		return nil, false, errors.New("SetupDiSetDeviceRegistryProperty(SPDRP_HARDWAREID) failed: " + err.Error())
	}

	// Search for the driver.
	const driverType = setupapi.SPDIT_CLASSDRIVER
	err = devInfoList.BuildDriverInfoList(deviceData, driverType)
	if err != nil {
		return nil, false, errors.New("SetupDiBuildDriverInfoList failed: " + err.Error())
	}
	defer devInfoList.DestroyDriverInfoList(deviceData, driverType)

	driverDate := windows.Filetime{}
	driverVersion := uint64(0)
	for index := 0; ; index++ {
		// Get a driver from the list.
		driverData, err := devInfoList.EnumDriverInfo(deviceData, driverType, index)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			// Something is wrong with this driver. Skip it.
			continue
		}

		// Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for any driver versioned prior our best match.
		if driverData.IsNewer(driverDate, driverVersion) {
			// Get driver info details.
			driverDetailData, err := devInfoList.GetDriverInfoDetail(deviceData, driverData)
			if err != nil {
				// Something is wrong with this driver. Skip it.
				continue
			}

			if driverDetailData.IsCompatible(hardwareID) {
				// Matching hardware ID found. Select the driver.
				err := devInfoList.SetSelectedDriver(deviceData, driverData)
				if err != nil {
					// Something is wrong with this driver. Skip it.
					continue
				}

				driverDate = driverData.DriverDate
				driverVersion = driverData.DriverVersion
			}
		}
	}

	if driverVersion == 0 {
		return nil, false, fmt.Errorf("No driver for device %q installed", hardwareID)
	}

	// Call appropriate class installer.
	err = devInfoList.CallClassInstaller(setupapi.DIF_REGISTERDEVICE, deviceData)
	if err != nil {
		return nil, false, errors.New("SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed: " + err.Error())
	}

	// Register device co-installers if any. (Ignore errors)
	devInfoList.CallClassInstaller(setupapi.DIF_REGISTER_COINSTALLERS, deviceData)

	// Install interfaces if any. (Ignore errors)
	devInfoList.CallClassInstaller(setupapi.DIF_INSTALLINTERFACES, deviceData)

	var wintun *Wintun
	var rebootRequired bool

	// Install the device.
	err = devInfoList.CallClassInstaller(setupapi.DIF_INSTALLDEVICE, deviceData)
	if err != nil {
		err = errors.New("SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed: " + err.Error())
	}

	if err == nil {
		// Check if a system reboot is required. (Ignore errors)
		if ret, _ := checkReboot(devInfoList, deviceData); ret {
			rebootRequired = true
		}

		// Get network interface. DIF_INSTALLDEVICE returns almost immediately, while the device
		// installation continues in the background. It might take a while, before all registry
		// keys and values are populated.
		for numAttempts := 0; numAttempts < 30; numAttempts++ {
			wintun, err = MakeWintun(devInfoList, deviceData)
			if err != nil {
				if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_FILE_NOT_FOUND {
					// Wait and retry. TODO: Wait for a cancellable event instead.
					err = errors.New("Time-out waiting for adapter to get ready")
					time.Sleep(time.Second / 4)
					continue
				}
			}

			break
		}
	}

	if err == nil {
		return wintun, rebootRequired, nil
	}

	// The interface failed to install, or the interface ID was unobtainable. Clean-up.
	removeDeviceParams := setupapi.RemoveDeviceParams{
		ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
		Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
	}

	// Set class installer parameters for DIF_REMOVE.
	if devInfoList.SetClassInstallParams(deviceData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams))) == nil {
		// Call appropriate class installer.
		if devInfoList.CallClassInstaller(setupapi.DIF_REMOVE, deviceData) == nil {
			// Check if a system reboot is required. (Ignore errors)
			if ret, _ := checkReboot(devInfoList, deviceData); ret {
				rebootRequired = true
			}
		}
	}

	return nil, rebootRequired, err
}

//
// DeleteInterface deletes a TUN interface.
//
// hwndParent is a handle to the top-level window to use for any user
// interface that is related to non-device-specific actions (such as a select-
// device dialog box that uses the global class driver list). This handle is
// optional and can be 0. If a specific top-level window is not required, set
// hwndParent to 0.
//
// Function returns true if the interface was found and deleted and a flag if
// reboot is required.
//
func (wintun *Wintun) DeleteInterface(hwndParent uintptr) (bool, bool, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, enumerator, hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), machineName)
	if err != nil {
		return false, false, errors.New(fmt.Sprintf("SetupDiGetClassDevsEx(%v) failed: ", guid.ToString(&deviceClassNetGUID)) + err.Error())
	}
	defer devInfoList.Close()

	// Iterate.
	for index := 0; ; index++ {
		// Get the device from the list. Should anything be wrong with this device, continue with next.
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}

		// Get interface ID.
		wintun2, err := MakeWintun(devInfoList, deviceData)
		if err != nil {
			continue
		}

		if wintun.CfgInstanceID == wintun2.CfgInstanceID {
			// Remove the device.
			removeDeviceParams := setupapi.RemoveDeviceParams{
				ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
				Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
			}

			// Set class installer parameters for DIF_REMOVE.
			err = devInfoList.SetClassInstallParams(deviceData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams)))
			if err != nil {
				return false, false, errors.New("SetupDiSetClassInstallParams failed: " + err.Error())
			}

			// Call appropriate class installer.
			err = devInfoList.CallClassInstaller(setupapi.DIF_REMOVE, deviceData)
			if err != nil {
				return false, false, errors.New("SetupDiCallClassInstaller failed: " + err.Error())
			}

			// Check if a system reboot is required. (Ignore errors)
			if ret, _ := checkReboot(devInfoList, deviceData); ret {
				return true, true, nil
			}

			return true, false, nil
		}
	}

	return false, false, nil
}

//
// FlushInterface removes all properties from the interface and gives it only a very
// vanilla IPv4 and IPv6 configuration with no addresses of any sort assigned.
//
func (wintun *Wintun) FlushInterface() error {
	//TODO: implement me!
	return nil
}

//
// checkReboot checks device install parameters if a system reboot is required.
//
func checkReboot(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) (bool, error) {
	devInstallParams, err := deviceInfoSet.GetDeviceInstallParams(deviceInfoData)
	if err != nil {
		return false, err
	}

	if (devInstallParams.Flags & (setupapi.DI_NEEDREBOOT | setupapi.DI_NEEDRESTART)) != 0 {
		return true, nil
	}

	return false, nil
}

//
// GetInterfaceName returns network interface name.
//
func (wintun *Wintun) GetInterfaceName() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.GetNetRegKeyName(), registry.QUERY_VALUE)
	if err != nil {
		return "", errors.New("Network-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	// Get the interface name.
	return getRegStringValue(key, "Name")
}

//
// SetInterfaceName sets network interface name.
//
func (wintun *Wintun) SetInterfaceName(ifname string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.GetNetRegKeyName(), registry.SET_VALUE)
	if err != nil {
		return errors.New("Network-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	// Set the interface name.
	return key.SetStringValue("Name", ifname)
}

//
// GetNetRegKeyName returns interface-specific network registry key name.
//
func (wintun *Wintun) GetNetRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guid.ToString(&deviceClassNetGUID), guid.ToString(&wintun.CfgInstanceID))
}

//
// getRegStringValue function reads a string value from registry.
//
// If the value type is REG_EXPAND_SZ the environment variables are expanded.
// Should expanding fail, original string value and nil error are returned.
//
func getRegStringValue(key registry.Key, name string) (string, error) {
	// Read string value.
	value, valueType, err := key.GetStringValue(name)
	if err != nil {
		return "", err
	}

	if valueType != registry.EXPAND_SZ {
		// Value does not require expansion.
		return value, nil
	}

	valueExp, err := registry.ExpandString(value)
	if err != nil {
		// Expanding failed: return original sting value.
		return value, nil
	}

	// Return expanded value.
	return valueExp, nil
}

//
// DataFileName returns Wintun device data pipe name.
//
func (wintun *Wintun) DataFileName() string {
	return fmt.Sprintf("\\\\.\\Global\\WINTUN%d", wintun.LUIDIndex)
}
