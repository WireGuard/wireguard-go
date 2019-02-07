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

	"git.zx2c4.com/wireguard-go/tun/wintun/guid"
	"git.zx2c4.com/wireguard-go/tun/wintun/setupapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Wintun windows.GUID

var deviceClassNetGUID = windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

const TUN_HWID = "Wintun"

//
// GetInterface finds interface ID by name.
//
// hwndParent is a handle to the top-level window to use for any user
// interface that is related to non-device-specific actions (such as a select-
// device dialog box that uses the global class driver list). This handle is
// optional and can be 0. If a specific top-level window is not required, set
// hwndParent to 0.
//
// Function returns interface ID when the interface was found, or nil
// otherwise.
//
func GetInterface(ifname string, hwndParent uintptr) (*Wintun, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return nil, err
	}
	defer devInfoList.Close()

	// Retrieve information associated with a device information set.
	// TODO: Is this really necessary?
	_, err = devInfoList.GetDeviceInfoListDetail()
	if err != nil {
		return nil, err
	}

	// TODO: If we're certain we want case-insensitive name comparison, please document the rationale.
	ifname = strings.ToLower(ifname)

	// Iterate.
	for index := 0; ; index++ {
		// Get the device from the list.
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			// Something is wrong with this device. Skip it.
			continue
		}

		// Get interface ID.
		ifid, err := getInterfaceId(devInfoList, deviceData, 1)
		if err != nil {
			// Something is wrong with this device. Skip it.
			continue
		}

		// Get interface name.
		ifname2, err := ((*Wintun)(ifid)).GetInterfaceName()
		if err != nil {
			// Something is wrong with this device. Skip it.
			continue
		}

		if ifname == strings.ToLower(ifname2) {
			// Interface name found.
			return (*Wintun)(ifid), nil
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
	devInfoList, err := setupapi.SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, hwndParent, "")
	if err != nil {
		return nil, false, err
	}

	// Get the device class name from GUID.
	className, err := setupapi.SetupDiClassNameFromGuidEx(&deviceClassNetGUID, "")
	if err != nil {
		return nil, false, err
	}

	// Create a new device info element and add it to the device info set.
	deviceData, err := devInfoList.CreateDeviceInfo(className, &deviceClassNetGUID, description, hwndParent, setupapi.DICD_GENERATE_ID)
	if err != nil {
		return nil, false, err
	}

	// Set a device information element as the selected member of a device information set.
	err = devInfoList.SetSelectedDevice(deviceData)
	if err != nil {
		return nil, false, err
	}

	// Set Plug&Play device hardware ID property.
	hwid, err := syscall.UTF16FromString(TUN_HWID)
	if err != nil {
		return nil, false, err
	}
	err = devInfoList.SetDeviceRegistryProperty(deviceData, setupapi.SPDRP_HARDWAREID, setupapi.UTF16ToBuf(append(hwid, 0)))
	if err != nil {
		return nil, false, err
	}

	// Search for the driver.
	const driverType = setupapi.SPDIT_CLASSDRIVER
	err = devInfoList.BuildDriverInfoList(deviceData, driverType)
	if err != nil {
		return nil, false, err
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

			if driverDetailData.IsCompatible(TUN_HWID) {
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
		return nil, false, fmt.Errorf("No driver for device \"%v\" installed", TUN_HWID)
	}

	// Call appropriate class installer.
	err = devInfoList.CallClassInstaller(setupapi.DIF_REGISTERDEVICE, deviceData)
	if err != nil {
		return nil, false, err
	}

	// Register device co-installers if any.
	devInfoList.CallClassInstaller(setupapi.DIF_REGISTER_COINSTALLERS, deviceData)

	// Install interfaces if any.
	devInfoList.CallClassInstaller(setupapi.DIF_INSTALLINTERFACES, deviceData)

	var ifid *windows.GUID
	var rebootRequired bool

	// Install the device.
	err = devInfoList.CallClassInstaller(setupapi.DIF_INSTALLDEVICE, deviceData)
	if err == nil {
		// Check if a system reboot is required. (Ignore errors)
		if ret, _ := checkReboot(devInfoList, deviceData); ret {
			rebootRequired = true
		}

		// Get network interface ID from registry. Retry for max 30sec.
		ifid, err = getInterfaceId(devInfoList, deviceData, 30)
	}

	if err == nil {
		return (*Wintun)(ifid), rebootRequired, nil
	}

	// The interface failed to install, or the interface ID was unobtainable. Clean-up.
	removeDeviceParams := setupapi.SP_REMOVEDEVICE_PARAMS{
		ClassInstallHeader: setupapi.SP_CLASSINSTALL_HEADER{
			InstallFunction: setupapi.DIF_REMOVE,
		},
		Scope: setupapi.DI_REMOVEDEVICE_GLOBAL,
	}
	removeDeviceParams.ClassInstallHeader.Size = uint32(unsafe.Sizeof(removeDeviceParams.ClassInstallHeader))

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

	return nil, false, err
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
	ifid := (*windows.GUID)(wintun)
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return false, false, err
	}
	defer devInfoList.Close()

	// Retrieve information associated with a device information set.
	// TODO: Is this really necessary?
	_, err = devInfoList.GetDeviceInfoListDetail()
	if err != nil {
		return false, false, err
	}

	// Iterate.
	for index := 0; ; index++ {
		// Get the device from the list.
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			// Something is wrong with this device. Skip it.
			continue
		}

		// Get interface ID.
		ifid2, err := getInterfaceId(devInfoList, deviceData, 1)
		if err != nil {
			// Something is wrong with this device. Skip it.
			continue
		}

		if *ifid == *ifid2 {
			// Remove the device.
			removeDeviceParams := setupapi.SP_REMOVEDEVICE_PARAMS{
				ClassInstallHeader: setupapi.SP_CLASSINSTALL_HEADER{
					InstallFunction: setupapi.DIF_REMOVE,
				},
				Scope: setupapi.DI_REMOVEDEVICE_GLOBAL,
			}
			removeDeviceParams.ClassInstallHeader.Size = uint32(unsafe.Sizeof(removeDeviceParams.ClassInstallHeader))

			// Set class installer parameters for DIF_REMOVE.
			err = devInfoList.SetClassInstallParams(deviceData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams)))
			if err != nil {
				return false, false, err
			}

			// Call appropriate class installer.
			err = devInfoList.CallClassInstaller(setupapi.DIF_REMOVE, deviceData)
			if err != nil {
				return false, false, err
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

///
/// checkReboot checks device install parameters if a system reboot is required.
///
func checkReboot(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.SP_DEVINFO_DATA) (bool, error) {
	devInstallParams, err := deviceInfoSet.GetDeviceInstallParams(deviceInfoData)
	if err != nil {
		return false, err
	}

	if (devInstallParams.Flags & (setupapi.DI_NEEDREBOOT | setupapi.DI_NEEDRESTART)) != 0 {
		return true, nil
	}

	return false, nil
}

// getInterfaceId returns network interface ID.
//
// After the device is created, it might take some time before the registry
// key is populated. numAttempts parameter specifies the number of attempts
// to read NetCfgInstanceId value from registry. A 1sec sleep is inserted
// between retry attempts.
//
// Function returns the network interface ID.
//
func getInterfaceId(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.SP_DEVINFO_DATA, numAttempts int) (*windows.GUID, error) {
	if numAttempts < 1 {
		return nil, fmt.Errorf("Invalid numAttempts (expected: >=1, provided: %v)", numAttempts)
	}

	// Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key.
	key, err := deviceInfoSet.OpenDevRegKey(deviceInfoData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.READ)
	if err != nil {
		return nil, errors.New("Device-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	for {
		// Query the NetCfgInstanceId value. Using get_reg_string() right on might clutter the output with error messages while the registry is still being populated.
		_, _, err = key.GetValue("NetCfgInstanceId", nil)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_FILE_NOT_FOUND {
				numAttempts--
				if numAttempts > 0 {
					// Wait and retry.
					// TODO: Wait for a cancellable event instead.
					time.Sleep(1000 * time.Millisecond)
					continue
				}
			}

			return nil, errors.New("RegQueryValueEx(\"NetCfgInstanceId\") failed: " + err.Error())
		}

		// Read the NetCfgInstanceId value now.
		value, err := getRegStringValue(key, "NetCfgInstanceId")
		if err != nil {
			return nil, errors.New("RegQueryStringValue(\"NetCfgInstanceId\") failed: " + err.Error())
		}

		// Convert to windows.GUID.
		ifid, err := guid.FromString(value)
		if err != nil {
			return nil, fmt.Errorf("NetCfgInstanceId registry value is not a GUID (expected: \"{...}\", provided: \"%v\")", value)
		}

		return ifid, err
	}
}

//
// GetInterfaceName returns network interface name.
//
func (wintun *Wintun) GetInterfaceName() (string, error) {
	ifid := (*windows.GUID)(wintun)
	// Open network interface registry key.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guid.ToString(&deviceClassNetGUID), guid.ToString(ifid)), registry.QUERY_VALUE)
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
	ifid := (*windows.GUID)(wintun)
	// Open network interface registry key.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guid.ToString(&deviceClassNetGUID), guid.ToString(ifid)), registry.SET_VALUE)
	if err != nil {
		return errors.New("Network-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	// Set the interface name.
	return key.SetStringValue("Name", ifname)
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

func (wintun *Wintun) SignalEventName() string {
	return fmt.Sprintf("Global\\WINTUN_EVENT_%s", guid.ToString((*windows.GUID)(wintun)))
}

func (wintun *Wintun) DataFileName() string {
	return fmt.Sprintf("\\\\.\\Global\\WINTUN_DEVICE_%s", guid.ToString((*windows.GUID)(wintun)))
}