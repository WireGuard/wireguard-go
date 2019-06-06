/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"golang.zx2c4.com/wireguard/tun/wintun/netshell"
	registryEx "golang.zx2c4.com/wireguard/tun/wintun/registry"
	"golang.zx2c4.com/wireguard/tun/wintun/setupapi"
)

//
// Wintun is a handle of a Wintun adapter
//
type Wintun struct {
	cfgInstanceID windows.GUID
	luidIndex     uint32
	ifType        uint32
}

var deviceClassNetGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

const hardwareID = "Wintun"
const enumerator = ""
const machineName = ""
const waitForRegistryTimeout = time.Second * 5

//
// MakeWintun creates interface handle and populates it from device registry key
//
func makeWintun(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) (*Wintun, error) {
	// Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key.
	key, err := deviceInfoSet.OpenDevRegKey(deviceInfoData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("Device-specific registry key open failed: %v", err)
	}
	defer key.Close()

	// Read the NetCfgInstanceId value.
	valueStr, err := registryEx.GetStringValue(key, "NetCfgInstanceId")
	if err != nil {
		return nil, fmt.Errorf("RegQueryStringValue(\"NetCfgInstanceId\") failed: %v", err)
	}

	// Convert to GUID.
	ifid, err := windows.GUIDFromString(valueStr)
	if err != nil {
		return nil, fmt.Errorf("NetCfgInstanceId registry value is not a GUID (expected: \"{...}\", provided: %q)", valueStr)
	}

	// Read the NetLuidIndex value.
	luidIdx, _, err := key.GetIntegerValue("NetLuidIndex")
	if err != nil {
		return nil, fmt.Errorf("RegQueryValue(\"NetLuidIndex\") failed: %v", err)
	}

	// Read the NetLuidIndex value.
	ifType, _, err := key.GetIntegerValue("*IfType")
	if err != nil {
		return nil, fmt.Errorf("RegQueryValue(\"*IfType\") failed: %v", err)
	}

	return &Wintun{
		cfgInstanceID: ifid,
		luidIndex:     uint32(luidIdx),
		ifType:        uint32(ifType),
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
// Function returns interface if found, or windows.ERROR_OBJECT_NOT_FOUND
// otherwise. If the interface is found but not Wintun-class, the function
// returns windows.ERROR_ALREADY_EXISTS.
//
func GetInterface(ifname string, hwndParent uintptr) (*Wintun, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, enumerator, hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), machineName)
	if err != nil {
		return nil, fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err)
	}
	defer devInfoList.Close()

	// Windows requires each interface to have a different name. When
	// enforcing this, Windows treats interface names case-insensitive. If an
	// interface "FooBar" exists and this function reports there is no
	// interface "foobar", an attempt to create a new interface and name it
	// "foobar" would cause conflict with "FooBar".
	ifname = strings.ToLower(ifname)

	for index := 0; ; index++ {
		// Get the device from the list. Should anything be wrong with this device, continue with next.
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Get interface ID.
		wintun, err := makeWintun(devInfoList, deviceData)
		if err != nil {
			continue
		}

		//TODO: is there a better way than comparing ifnames?
		// Get interface name.
		ifname2, err := wintun.InterfaceName()
		if err != nil {
			continue
		}

		if ifname == strings.ToLower(ifname2) {
			// Interface name found. Check its driver.
			const driverType = setupapi.SPDIT_COMPATDRIVER
			err = devInfoList.BuildDriverInfoList(deviceData, driverType)
			if err != nil {
				return nil, fmt.Errorf("SetupDiBuildDriverInfoList failed: %v", err)
			}
			defer devInfoList.DestroyDriverInfoList(deviceData, driverType)

			for index := 0; ; index++ {
				// Get a driver from the list.
				driverData, err := devInfoList.EnumDriverInfo(deviceData, driverType, index)
				if err != nil {
					if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
						break
					}
					// Something is wrong with this driver. Skip it.
					continue
				}

				// Get driver info details.
				driverDetailData, err := devInfoList.DriverInfoDetail(deviceData, driverData)
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
			return nil, windows.ERROR_ALREADY_EXISTS
		}
	}

	return nil, windows.ERROR_OBJECT_NOT_FOUND
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
		return nil, false, fmt.Errorf("SetupDiCreateDeviceInfoListEx(%v) failed: %v", deviceClassNetGUID, err)
	}
	defer devInfoList.Close()

	// Get the device class name from GUID.
	className, err := setupapi.SetupDiClassNameFromGuidEx(&deviceClassNetGUID, machineName)
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiClassNameFromGuidEx(%v) failed: %v", deviceClassNetGUID, err)
	}

	// Create a new device info element and add it to the device info set.
	deviceData, err := devInfoList.CreateDeviceInfo(className, &deviceClassNetGUID, description, hwndParent, setupapi.DICD_GENERATE_ID)
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiCreateDeviceInfo failed: %v", err)
	}

	if hwndParent == 0 {
		err = setQuietInstall(devInfoList, deviceData)
		if err != nil {
			return nil, false, fmt.Errorf("Setting quiet installation failed: %v", err)
		}
	}

	// Set a device information element as the selected member of a device information set.
	err = devInfoList.SetSelectedDevice(deviceData)
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiSetSelectedDevice failed: %v", err)
	}

	// Set Plug&Play device hardware ID property.
	err = devInfoList.SetDeviceRegistryPropertyString(deviceData, setupapi.SPDRP_HARDWAREID, hardwareID)
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiSetDeviceRegistryProperty(SPDRP_HARDWAREID) failed: %v", err)
	}

	// Search for the driver.
	const driverType = setupapi.SPDIT_COMPATDRIVER
	err = devInfoList.BuildDriverInfoList(deviceData, driverType) //TODO: This takes ~510ms
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiBuildDriverInfoList failed: %v", err)
	}
	defer devInfoList.DestroyDriverInfoList(deviceData, driverType)

	driverDate := windows.Filetime{}
	driverVersion := uint64(0)
	for index := 0; ; index++ { //TODO: This loop takes ~600ms
		// Get a driver from the list.
		driverData, err := devInfoList.EnumDriverInfo(deviceData, driverType, index)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			// Something is wrong with this driver. Skip it.
			continue
		}

		// Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for any driver versioned prior our best match.
		if driverData.IsNewer(driverDate, driverVersion) {
			// Get driver info details.
			driverDetailData, err := devInfoList.DriverInfoDetail(deviceData, driverData)
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
		return nil, false, fmt.Errorf("SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed: %v", err)
	}

	// Register device co-installers if any. (Ignore errors)
	devInfoList.CallClassInstaller(setupapi.DIF_REGISTER_COINSTALLERS, deviceData)

	// Install interfaces if any. (Ignore errors)
	devInfoList.CallClassInstaller(setupapi.DIF_INSTALLINTERFACES, deviceData)

	// Install the device.
	err = devInfoList.CallClassInstaller(setupapi.DIF_INSTALLDEVICE, deviceData)
	if err != nil {
		err = fmt.Errorf("SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed: %v", err)
	}

	var wintun *Wintun
	var rebootRequired bool
	var key registry.Key

	if err == nil {
		// Check if a system reboot is required. (Ignore errors)
		if ret, _ := checkReboot(devInfoList, deviceData); ret {
			rebootRequired = true
		}

		// DIF_INSTALLDEVICE returns almost immediately, while the device installation
		// continues in the background. It might take a while, before all registry
		// keys and values are populated.
		const pollTimeout = time.Millisecond * 50
		for i := 0; i < int(waitForRegistryTimeout/pollTimeout); i++ {
			if i != 0 {
				time.Sleep(pollTimeout)
			}
			key, err = devInfoList.OpenDevRegKey(deviceData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.QUERY_VALUE|registry.NOTIFY)
			if err == nil {
				break
			}
		}
		if err == nil {
			_, err = registryEx.GetStringValueWait(key, "NetCfgInstanceId", waitForRegistryTimeout)
			if err == nil {
				_, err = registryEx.GetIntegerValueWait(key, "NetLuidIndex", waitForRegistryTimeout)
			}
			if err == nil {
				_, err = registryEx.GetIntegerValueWait(key, "*IfType", waitForRegistryTimeout)
			}
			key.Close()
		}
	}

	if err == nil {
		// Get network interface.
		wintun, err = makeWintun(devInfoList, deviceData)
	}

	if err == nil {
		// Wait for network registry key to emerge and populate.
		key, err = registryEx.OpenKeyWait(
			registry.LOCAL_MACHINE,
			wintun.netRegKeyName(),
			registry.QUERY_VALUE|registry.NOTIFY,
			waitForRegistryTimeout)
		if err == nil {
			_, err = registryEx.GetStringValueWait(key, "Name", waitForRegistryTimeout)
			key.Close()
		}
	}

	if err == nil {
		// Wait for TCP/IP adapter registry key to emerge and populate.
		key, err = registryEx.OpenKeyWait(
			registry.LOCAL_MACHINE,
			wintun.tcpipAdapterRegKeyName(), registry.QUERY_VALUE|registry.NOTIFY,
			waitForRegistryTimeout)
		if err == nil {
			_, err = registryEx.GetStringValueWait(key, "IpConfig", waitForRegistryTimeout)
			key.Close()
		}
	}

	var tcpipInterfaceRegKeyName string
	if err == nil {
		tcpipInterfaceRegKeyName, err = wintun.tcpipInterfaceRegKeyName()
		if err == nil {
			// Wait for TCP/IP interface registry key to emerge.
			key, err = registryEx.OpenKeyWait(
				registry.LOCAL_MACHINE,
				tcpipInterfaceRegKeyName, registry.QUERY_VALUE,
				waitForRegistryTimeout)
			if err == nil {
				key.Close()
			}
		}
	}

	//
	// All the registry keys and values we're relying on are present now.
	//

	if err == nil {
		// Disable dead gateway detection on our interface.
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfaceRegKeyName, registry.SET_VALUE)
		if err != nil {
			err = fmt.Errorf("Error opening interface-specific TCP/IP network registry key: %v", err)
		}
		key.SetDWordValue("EnableDeadGWDetect", 0)
		key.Close()
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
// Function silently succeeds if the interface was not found.
//
// Function returns true if a reboot is required.
//
func (wintun *Wintun) DeleteInterface(hwndParent uintptr) (bool, error) {
	devInfoList, deviceData, err := wintun.deviceData(hwndParent)
	if err == windows.ERROR_OBJECT_NOT_FOUND {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer devInfoList.Close()

	// Remove the device.
	removeDeviceParams := setupapi.RemoveDeviceParams{
		ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
		Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
	}

	// Set class installer parameters for DIF_REMOVE.
	err = devInfoList.SetClassInstallParams(deviceData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams)))
	if err != nil {
		return false, fmt.Errorf("SetupDiSetClassInstallParams failed: %v", err)
	}

	// Call appropriate class installer.
	err = devInfoList.CallClassInstaller(setupapi.DIF_REMOVE, deviceData)
	if err != nil {
		return false, fmt.Errorf("SetupDiCallClassInstaller failed: %v", err)
	}

	// Check if a system reboot is required. (Ignore errors)
	ret, _ := checkReboot(devInfoList, deviceData)
	return ret, nil
}

//
// checkReboot checks device install parameters if a system reboot is required.
//
func checkReboot(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) (bool, error) {
	devInstallParams, err := deviceInfoSet.DeviceInstallParams(deviceInfoData)
	if err != nil {
		return false, err
	}

	return (devInstallParams.Flags & (setupapi.DI_NEEDREBOOT | setupapi.DI_NEEDRESTART)) != 0, nil
}

//
// setQuietInstall sets device install parameters for a quiet installation
//
func setQuietInstall(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) error {
	devInstallParams, err := deviceInfoSet.DeviceInstallParams(deviceInfoData)
	if err != nil {
		return err
	}

	devInstallParams.Flags |= setupapi.DI_QUIETINSTALL
	return deviceInfoSet.SetDeviceInstallParams(deviceInfoData, devInstallParams)
}

//
// InterfaceName returns network interface name.
//
func (wintun *Wintun) InterfaceName() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.netRegKeyName(), registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("Network-specific registry key open failed: %v", err)
	}
	defer key.Close()

	// Get the interface name.
	return registryEx.GetStringValue(key, "Name")
}

//
// SetInterfaceName sets network interface name.
//
func (wintun *Wintun) SetInterfaceName(ifname string) error {
	// We have to tell the various runtime COM services about the new name too. We ignore the
	// error because netshell isn't available on servercore.
	// TODO: netsh.exe falls back to NciSetConnection in this case. If somebody complains, maybe
	// we should do the same.
	netshell.HrRenameConnection(&wintun.cfgInstanceID, windows.StringToUTF16Ptr(ifname))

	// Set the interface name. The above line should have done this too, but in case it failed, we force it.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.netRegKeyName(), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("Network-specific registry key open failed: %v", err)
	}
	defer key.Close()
	return key.SetStringValue("Name", ifname)
}

//
// netRegKeyName returns interface-specific network registry key name.
//
func (wintun *Wintun) netRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", deviceClassNetGUID, wintun.cfgInstanceID)
}

//
// tcpipAdapterRegKeyName returns adapter-specific TCP/IP network registry key name.
//
func (wintun *Wintun) tcpipAdapterRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%v", wintun.cfgInstanceID)
}

//
// tcpipInterfaceRegKeyName returns interface-specific TCP/IP network registry key name.
//
func (wintun *Wintun) tcpipInterfaceRegKeyName() (path string, err error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.tcpipAdapterRegKeyName(), registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("Error opening adapter-specific TCP/IP network registry key: %v", err)
	}
	paths, _, err := key.GetStringsValue("IpConfig")
	key.Close()
	if err != nil {
		return "", fmt.Errorf("Error reading IpConfig registry key: %v", err)
	}
	if len(paths) == 0 {
		return "", errors.New("No TCP/IP interfaces found on adapter")
	}
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\%s", paths[0]), nil
}

//
// deviceData returns TUN device info list handle and interface device info
// data.
//
// The device info list handle must be closed after use.
//
// In case the device is not found, windows.ERROR_OBJECT_NOT_FOUND is
// returned.
//
func (wintun *Wintun) deviceData(hwndParent uintptr) (setupapi.DevInfo, *setupapi.DevInfoData, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, enumerator, hwndParent, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), machineName)
	if err != nil {
		return 0, nil, fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err.Error())
	}

	// Iterate.
	for index := 0; ; index++ {
		// Get the device from the list. Should anything be wrong with this device, continue with next.
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if errWin, ok := err.(windows.Errno); ok && errWin == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Get interface ID.
		//TODO: Store some ID in the Wintun object such that this call isn't required.
		wintun2, err := makeWintun(devInfoList, deviceData)
		if err != nil {
			continue
		}

		if wintun.cfgInstanceID == wintun2.cfgInstanceID {
			if hwndParent == 0 {
				err = setQuietInstall(devInfoList, deviceData)
				if err != nil {
					devInfoList.Close()
					return 0, nil, fmt.Errorf("Setting quiet installation failed: %v", err)
				}
			}

			return devInfoList, deviceData, nil
		}
	}

	devInfoList.Close()
	return 0, nil, windows.ERROR_OBJECT_NOT_FOUND
}

//
// DataFileName returns Wintun device data pipe name.
//
func (wintun *Wintun) DataFileName() string {
	return fmt.Sprintf("\\\\.\\Global\\WINTUN%d", wintun.luidIndex)
}

//
// GUID returns the GUID of the interface.
//
func (wintun *Wintun) GUID() windows.GUID {
	return wintun.cfgInstanceID
}

//
// LUID returns the LUID of the interface.
//
func (wintun *Wintun) LUID() uint64 {
	return ((uint64(wintun.luidIndex) & ((1 << 24) - 1)) << 24) | ((uint64(wintun.ifType) & ((1 << 16) - 1)) << 48)
}
