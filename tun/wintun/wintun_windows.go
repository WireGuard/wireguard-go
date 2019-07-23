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

// Wintun is a handle of a Wintun adapter.
type Wintun struct {
	cfgInstanceID windows.GUID
	devInstanceID string
	luidIndex     uint32
	ifType        uint32
}

var deviceClassNetGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var deviceInterfaceNetGUID = windows.GUID{Data1: 0xcac88484, Data2: 0x7515, Data3: 0x4c03, Data4: [8]byte{ 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61}}

const (
	hardwareID             = "Wintun"
	waitForRegistryTimeout = time.Second * 10
)

// makeWintun creates a Wintun interface handle and populates it from the device's registry key.
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

	instanceId, err := deviceInfoSet.DeviceInstanceID(deviceInfoData)
	if err != nil {
		return nil, fmt.Errorf("DeviceInstanceID failed: %v", err)
	}

	return &Wintun{
		cfgInstanceID: ifid,
		devInstanceID: instanceId,
		luidIndex:     uint32(luidIdx),
		ifType:        uint32(ifType),
	}, nil
}

// GetInterface finds a Wintun interface by its name. This function returns
// the interface if found, or windows.ERROR_OBJECT_NOT_FOUND otherwise. If
// the interface is found but not a Wintun-class, this function returns
// windows.ERROR_ALREADY_EXISTS.
func GetInterface(ifname string) (*Wintun, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
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
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		wintun, err := makeWintun(devInfoList, deviceData)
		if err != nil {
			continue
		}

		// TODO: is there a better way than comparing ifnames?
		ifname2, err := wintun.InterfaceName()
		if err != nil {
			continue
		}

		if ifname == strings.ToLower(ifname2) {
			err = devInfoList.BuildDriverInfoList(deviceData, setupapi.SPDIT_COMPATDRIVER)
			if err != nil {
				return nil, fmt.Errorf("SetupDiBuildDriverInfoList failed: %v", err)
			}
			defer devInfoList.DestroyDriverInfoList(deviceData, setupapi.SPDIT_COMPATDRIVER)

			for index := 0; ; index++ {
				driverData, err := devInfoList.EnumDriverInfo(deviceData, setupapi.SPDIT_COMPATDRIVER, index)
				if err != nil {
					if err == windows.ERROR_NO_MORE_ITEMS {
						break
					}
					continue
				}

				// Get driver info details.
				driverDetailData, err := devInfoList.DriverInfoDetail(deviceData, driverData)
				if err != nil {
					continue
				}

				if driverDetailData.IsCompatible(hardwareID) {
					return wintun, nil
				}
			}

			// This interface is not using Wintun driver.
			return nil, windows.ERROR_ALREADY_EXISTS
		}
	}

	return nil, windows.ERROR_OBJECT_NOT_FOUND
}

// CreateInterface creates a Wintun interface. description is a string that
// supplies the text description of the device. The description is optional
// and can be "". requestedGUID is the GUID of the created network interface,
// which then influences NLA generation deterministically. If it is set to nil,
// the GUID is chosen by the system at random, and hence a new NLA entry is
// created for each new interface. It is called "requested" GUID because the
// API it uses is completely undocumented, and so there could be minor
// interesting complications with its usage. This function returns the network
// interface ID and a flag if reboot is required.
//
func CreateInterface(description string, requestedGUID *windows.GUID) (wintun *Wintun, rebootRequired bool, err error) {
	// Create an empty device info set for network adapter device class.
	devInfoList, err := setupapi.SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, 0, "")
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiCreateDeviceInfoListEx(%v) failed: %v", deviceClassNetGUID, err)
	}
	defer devInfoList.Close()

	// Get the device class name from GUID.
	className, err := setupapi.SetupDiClassNameFromGuidEx(&deviceClassNetGUID, "")
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiClassNameFromGuidEx(%v) failed: %v", deviceClassNetGUID, err)
	}

	// Create a new device info element and add it to the device info set.
	deviceData, err := devInfoList.CreateDeviceInfo(className, &deviceClassNetGUID, description, 0, setupapi.DICD_GENERATE_ID)
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiCreateDeviceInfo failed: %v", err)
	}

	err = setQuietInstall(devInfoList, deviceData)
	if err != nil {
		return nil, false, fmt.Errorf("Setting quiet installation failed: %v", err)
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

	err = devInfoList.BuildDriverInfoList(deviceData, setupapi.SPDIT_COMPATDRIVER) // TODO: This takes ~510ms
	if err != nil {
		return nil, false, fmt.Errorf("SetupDiBuildDriverInfoList failed: %v", err)
	}
	defer devInfoList.DestroyDriverInfoList(deviceData, setupapi.SPDIT_COMPATDRIVER)

	driverDate := windows.Filetime{}
	driverVersion := uint64(0)
	for index := 0; ; index++ { // TODO: This loop takes ~600ms
		driverData, err := devInfoList.EnumDriverInfo(deviceData, setupapi.SPDIT_COMPATDRIVER, index)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for any driver versioned prior our best match.
		if driverData.IsNewer(driverDate, driverVersion) {
			driverDetailData, err := devInfoList.DriverInfoDetail(deviceData, driverData)
			if err != nil {
				continue
			}

			if driverDetailData.IsCompatible(hardwareID) {
				err := devInfoList.SetSelectedDriver(deviceData, driverData)
				if err != nil {
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

	if requestedGUID != nil {
		key, err := devInfoList.OpenDevRegKey(deviceData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.SET_VALUE)
		if err != nil {
			return nil, false, fmt.Errorf("OpenDevRegKey failed: %v", err)
		}
		err = key.SetStringValue("NetSetupAnticipatedInstanceId", requestedGUID.String())
		key.Close()
		if err != nil {
			return nil, false, fmt.Errorf("SetStringValue(NetSetupAnticipatedInstanceId) failed: %v", err)
		}
	}

	// Install interfaces if any. (Ignore errors)
	devInfoList.CallClassInstaller(setupapi.DIF_INSTALLINTERFACES, deviceData)

	// Install the device.
	err = devInfoList.CallClassInstaller(setupapi.DIF_INSTALLDEVICE, deviceData)
	if err != nil {
		err = fmt.Errorf("SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed: %v", err)
	}

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
			if err == nil {
				_, err = registryEx.GetStringValueWait(key, "PnPInstanceId", waitForRegistryTimeout)
			}
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

// DeleteInterface deletes a Wintun interface. This function succeeds
// if the interface was not found. It returns a bool indicating whether
// a reboot is required.
func (wintun *Wintun) DeleteInterface() (rebootRequired bool, err error) {
	devInfoList, deviceData, err := wintun.deviceData()
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
	rebootRequired, _ = checkReboot(devInfoList, deviceData)
	return rebootRequired, nil
}

// DeleteAllInterfaces deletes all Wintun interfaces, and returns which
// ones it deleted, whether a reboot is required after, and which errors
// occurred during the process.
func DeleteAllInterfaces() (deviceInstancesDeleted []uint32, rebootRequired bool, errors []error) {
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return nil, false, []error{fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err.Error())}
	}
	defer devInfoList.Close()

	for i := 0; ; i++ {
		deviceData, err := devInfoList.EnumDeviceInfo(i)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		err = devInfoList.BuildDriverInfoList(deviceData, setupapi.SPDIT_COMPATDRIVER)
		if err != nil {
			continue
		}
		defer devInfoList.DestroyDriverInfoList(deviceData, setupapi.SPDIT_COMPATDRIVER)

		isWintun := false
		for j := 0; ; j++ {
			driverData, err := devInfoList.EnumDriverInfo(deviceData, setupapi.SPDIT_COMPATDRIVER, j)
			if err != nil {
				if err == windows.ERROR_NO_MORE_ITEMS {
					break
				}
				continue
			}
			driverDetailData, err := devInfoList.DriverInfoDetail(deviceData, driverData)
			if err != nil {
				continue
			}
			if driverDetailData.IsCompatible(hardwareID) {
				isWintun = true
				break
			}
		}
		if !isWintun {
			continue
		}

		err = setQuietInstall(devInfoList, deviceData)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		inst := deviceData.DevInst
		removeDeviceParams := setupapi.RemoveDeviceParams{
			ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
			Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
		}
		err = devInfoList.SetClassInstallParams(deviceData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams)))
		if err != nil {
			errors = append(errors, err)
			continue
		}
		err = devInfoList.CallClassInstaller(setupapi.DIF_REMOVE, deviceData)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if !rebootRequired {
			rebootRequired, _ = checkReboot(devInfoList, deviceData)
		}
		deviceInstancesDeleted = append(deviceInstancesDeleted, inst)
	}
	return
}

// checkReboot checks device install parameters if a system reboot is required.
func checkReboot(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) (bool, error) {
	devInstallParams, err := deviceInfoSet.DeviceInstallParams(deviceInfoData)
	if err != nil {
		return false, err
	}

	return (devInstallParams.Flags & (setupapi.DI_NEEDREBOOT | setupapi.DI_NEEDRESTART)) != 0, nil
}

// setQuietInstall sets device install parameters for a quiet installation
func setQuietInstall(deviceInfoSet setupapi.DevInfo, deviceInfoData *setupapi.DevInfoData) error {
	devInstallParams, err := deviceInfoSet.DeviceInstallParams(deviceInfoData)
	if err != nil {
		return err
	}

	devInstallParams.Flags |= setupapi.DI_QUIETINSTALL
	return deviceInfoSet.SetDeviceInstallParams(deviceInfoData, devInstallParams)
}

// InterfaceName returns the name of the Wintun interface.
func (wintun *Wintun) InterfaceName() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.netRegKeyName(), registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("Network-specific registry key open failed: %v", err)
	}
	defer key.Close()

	// Get the interface name.
	return registryEx.GetStringValue(key, "Name")
}

// SetInterfaceName sets name of the Wintun interface.
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

// netRegKeyName returns the interface-specific network registry key name.
func (wintun *Wintun) netRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", deviceClassNetGUID, wintun.cfgInstanceID)
}

// tcpipAdapterRegKeyName returns the adapter-specific TCP/IP network registry key name.
func (wintun *Wintun) tcpipAdapterRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%v", wintun.cfgInstanceID)
}

// tcpipInterfaceRegKeyName returns the interface-specific TCP/IP network registry key name.
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

// deviceData returns TUN device info list handle and interface device info
// data. The device info list handle must be closed after use. In case the
// device is not found, windows.ERROR_OBJECT_NOT_FOUND is returned.
func (wintun *Wintun) deviceData() (setupapi.DevInfo, *setupapi.DevInfoData, error) {
	// Create a list of network devices.
	devInfoList, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return 0, nil, fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err.Error())
	}

	for index := 0; ; index++ {
		deviceData, err := devInfoList.EnumDeviceInfo(index)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Get interface ID.
		// TODO: Store some ID in the Wintun object such that this call isn't required.
		wintun2, err := makeWintun(devInfoList, deviceData)
		if err != nil {
			continue
		}

		if wintun.cfgInstanceID == wintun2.cfgInstanceID {
			err = setQuietInstall(devInfoList, deviceData)
			if err != nil {
				devInfoList.Close()
				return 0, nil, fmt.Errorf("Setting quiet installation failed: %v", err)
			}
			return devInfoList, deviceData, nil
		}
	}

	devInfoList.Close()
	return 0, nil, windows.ERROR_OBJECT_NOT_FOUND
}

// AdapterHandle returns a handle to the adapter device object.
func (wintun *Wintun) AdapterHandle() (windows.Handle, error) {
	mangledPnpNode := strings.ReplaceAll(fmt.Sprintf("%s\\%s", wintun.devInstanceID, deviceInterfaceNetGUID.String()), "\\", "#")
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(fmt.Sprintf("\\\\.\\Global\\%s", mangledPnpNode)), windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("Open NDIS device failed: %v", err)
	}
	return handle, nil
}

// GUID returns the GUID of the interface.
func (wintun *Wintun) GUID() windows.GUID {
	return wintun.cfgInstanceID
}

// LUID returns the LUID of the interface.
func (wintun *Wintun) LUID() uint64 {
	return ((uint64(wintun.luidIndex) & ((1 << 24) - 1)) << 24) | ((uint64(wintun.ifType) & ((1 << 16) - 1)) << 48)
}
