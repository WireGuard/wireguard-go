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
type Wintun windows.GUID

var deviceClassNetGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

const hardwareID = "Wintun"

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
// otherwise. If the interface is found but not Wintun-class, the function
// returns interface ID with an error.
//
func GetInterface(ifname string, hwndParent uintptr) (*Wintun, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return nil, err
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
		ifid, err := devInfoList.GetInterfaceID(deviceData)
		if err != nil {
			continue
		}

		// Get interface name.
		ifname2, err := ((*Wintun)(ifid)).GetInterfaceName()
		if err != nil {
			continue
		}

		if ifname == strings.ToLower(ifname2) {
			// Interface name found. Check its driver.
			const driverType = setupapi.SPDIT_COMPATDRIVER
			err = devInfoList.BuildDriverInfoList(deviceData, driverType)
			if err != nil {
				return nil, err
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
					return (*Wintun)(ifid), nil
				}
			}

			// This interface is not using Wintun driver.
			return (*Wintun)(ifid), errors.New("Foreign network interface with the same name exists")
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
	hwid, err := syscall.UTF16FromString(hardwareID)
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
		return nil, false, fmt.Errorf("No driver for device \"%v\" installed", hardwareID)
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

		// Get network interface ID from registry. DIF_INSTALLDEVICE returns almost immediately,
		// while the device installation continues in the background. It might take a while, before
		// all registry keys and values are populated.
		getInterfaceID := func() (*windows.GUID, error) {
			// Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key.
			keyDev, err := devInfoList.OpenDevRegKey(deviceData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.READ)
			if err != nil {
				return nil, errors.New("Device-specific registry key open failed: " + err.Error())
			}
			defer keyDev.Close()

			// Read the NetCfgInstanceId value.
			value, err := getRegStringValue(keyDev, "NetCfgInstanceId")
			if err != nil {
				if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_FILE_NOT_FOUND {
					return nil, err
				}

				return nil, errors.New("RegQueryStringValue(\"NetCfgInstanceId\") failed: " + err.Error())
			}

			// Convert to windows.GUID.
			ifid, err := guid.FromString(value)
			if err != nil {
				return nil, fmt.Errorf("NetCfgInstanceId registry value is not a GUID (expected: \"{...}\", provided: \"%v\")", value)
			}

			keyNetName := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guid.ToString(&deviceClassNetGUID), value)
			keyNet, err := registry.OpenKey(registry.LOCAL_MACHINE, keyNetName, registry.QUERY_VALUE)
			if err != nil {
				if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_FILE_NOT_FOUND {
					return nil, err
				}

				return nil, errors.New(fmt.Sprintf("RegOpenKeyEx(\"%v\") failed: ", keyNetName) + err.Error())
			}
			defer keyNet.Close()

			// Query the interface name.
			_, valueType, err := keyNet.GetValue("Name", nil)
			if err != nil {
				if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_FILE_NOT_FOUND {
					return nil, err
				}

				return nil, errors.New("RegQueryValueEx(\"Name\") failed: " + err.Error())
			}
			switch valueType {
			case registry.SZ, registry.EXPAND_SZ:
			default:
				return nil, fmt.Errorf("Interface name registry value is not REG_SZ or REG_EXPAND_SZ (expected: %v or %v, provided: %v)", registry.SZ, registry.EXPAND_SZ, valueType)
			}

			// TUN interface is ready. (As far as we need it.)
			return ifid, nil
		}
		for numAttempts := 0; numAttempts < 30; numAttempts++ {
			ifid, err = getInterfaceID()
			if err != nil {
				if errWin, ok := err.(syscall.Errno); ok && errWin == windows.ERROR_FILE_NOT_FOUND {
					// Wait and retry. TODO: Wait for a cancellable event instead.
					time.Sleep(1000 * time.Millisecond)
					continue
				}
			}

			break
		}
	}

	if err == nil {
		return (*Wintun)(ifid), rebootRequired, nil
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
		ifid2, err := devInfoList.GetInterfaceID(deviceData)
		if err != nil {
			continue
		}

		if *ifid == *ifid2 {
			// Remove the device.
			removeDeviceParams := setupapi.RemoveDeviceParams{
				ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
				Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
			}

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
	key, err := wintun.openNetRegKey(registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()

	// Get the interface name.
	return getRegStringValue(key, "Name")
}

//
// SetInterfaceName sets network interface name.
//
func (wintun *Wintun) SetInterfaceName(ifname string) error {
	key, err := wintun.openNetRegKey(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	// Set the interface name.
	return key.SetStringValue("Name", ifname)
}

//
// openNetRegKey opens interface-specific network registry key.
//
func (wintun *Wintun) openNetRegKey(access uint32) (registry.Key, error) {
	ifid := (*windows.GUID)(wintun)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guid.ToString(&deviceClassNetGUID), guid.ToString(ifid)), access)
	if err != nil {
		return 0, errors.New("Network-specific registry key open failed: " + err.Error())
	}

	return key, nil
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
// SignalEventName returns Wintun device data-ready event name.
//
func (wintun *Wintun) SignalEventName() string {
	return fmt.Sprintf("Global\\WINTUN_EVENT_%s", guid.ToString((*windows.GUID)(wintun)))
}

//
// DataFileName returns Wintun device data pipe name.
//
func (wintun *Wintun) DataFileName() string {
	return fmt.Sprintf("\\\\.\\Global\\WINTUN_DEVICE_%s", guid.ToString((*windows.GUID)(wintun)))
}
