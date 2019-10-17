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

	"golang.zx2c4.com/wireguard/tun/wintun/iphlpapi"
	"golang.zx2c4.com/wireguard/tun/wintun/nci"
	registryEx "golang.zx2c4.com/wireguard/tun/wintun/registry"
	"golang.zx2c4.com/wireguard/tun/wintun/setupapi"
)

type Pool string

type Interface struct {
	cfgInstanceID windows.GUID
	devInstanceID string
	luidIndex     uint32
	ifType        uint32
	pool          Pool
}

var deviceClassNetGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var deviceInterfaceNetGUID = windows.GUID{Data1: 0xcac88484, Data2: 0x7515, Data3: 0x4c03, Data4: [8]byte{0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61}}

const (
	hardwareID             = "Wintun"
	waitForRegistryTimeout = time.Second * 10
)

// makeWintun creates a Wintun interface handle and populates it from the device's registry key.
func makeWintun(devInfo setupapi.DevInfo, devInfoData *setupapi.DevInfoData, pool Pool) (*Interface, error) {
	// Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key.
	key, err := devInfo.OpenDevRegKey(devInfoData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.QUERY_VALUE)
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

	instanceID, err := devInfo.DeviceInstanceID(devInfoData)
	if err != nil {
		return nil, fmt.Errorf("DeviceInstanceID failed: %v", err)
	}

	return &Interface{
		cfgInstanceID: ifid,
		devInstanceID: instanceID,
		luidIndex:     uint32(luidIdx),
		ifType:        uint32(ifType),
		pool:          pool,
	}, nil
}

func removeNumberedSuffix(ifname string) string {
	removed := strings.TrimRight(ifname, "0123456789")
	if removed != ifname && len(removed) > 1 && removed[len(removed)-1] == ' ' {
		return removed[:len(removed)-1]
	}
	return ifname
}

// GetInterface finds a Wintun interface by its name. This function returns
// the interface if found, or windows.ERROR_OBJECT_NOT_FOUND otherwise. If
// the interface is found but not a Wintun-class or a member of the pool,
// this function returns windows.ERROR_ALREADY_EXISTS.
func (pool Pool) GetInterface(ifname string) (*Interface, error) {
	mutex, err := pool.takeNameMutex()
	if err != nil {
		return nil, err
	}
	defer func() {
		windows.ReleaseMutex(mutex)
		windows.CloseHandle(mutex)
	}()

	// Create a list of network devices.
	devInfo, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return nil, fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err)
	}
	defer devInfo.Close()

	// Windows requires each interface to have a different name. When
	// enforcing this, Windows treats interface names case-insensitive. If an
	// interface "FooBar" exists and this function reports there is no
	// interface "foobar", an attempt to create a new interface and name it
	// "foobar" would cause conflict with "FooBar".
	ifname = strings.ToLower(ifname)

	for index := 0; ; index++ {
		devInfoData, err := devInfo.EnumDeviceInfo(index)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Check the Hardware ID to make sure it's a real Wintun device first. This avoids doing slow operations on non-Wintun devices.
		property, err := devInfo.DeviceRegistryProperty(devInfoData, setupapi.SPDRP_HARDWAREID)
		if err != nil {
			continue
		}
		if hwids, ok := property.([]string); ok && len(hwids) > 0 && hwids[0] != hardwareID {
			continue
		}

		wintun, err := makeWintun(devInfo, devInfoData, pool)
		if err != nil {
			continue
		}

		// TODO: is there a better way than comparing ifnames?
		ifname2, err := wintun.Name()
		if err != nil {
			continue
		}
		ifname2 = strings.ToLower(ifname2)
		ifname3 := removeNumberedSuffix(ifname2)

		if ifname == ifname2 || ifname == ifname3 {
			err = devInfo.BuildDriverInfoList(devInfoData, setupapi.SPDIT_COMPATDRIVER)
			if err != nil {
				return nil, fmt.Errorf("SetupDiBuildDriverInfoList failed: %v", err)
			}
			defer devInfo.DestroyDriverInfoList(devInfoData, setupapi.SPDIT_COMPATDRIVER)

			for index := 0; ; index++ {
				driverData, err := devInfo.EnumDriverInfo(devInfoData, setupapi.SPDIT_COMPATDRIVER, index)
				if err != nil {
					if err == windows.ERROR_NO_MORE_ITEMS {
						break
					}
					continue
				}

				// Get driver info details.
				driverDetailData, err := devInfo.DriverInfoDetail(devInfoData, driverData)
				if err != nil {
					continue
				}

				if driverDetailData.IsCompatible(hardwareID) {
					isMember, err := pool.isMember(devInfo, devInfoData)
					if err != nil {
						return nil, err
					}
					if !isMember {
						return nil, windows.ERROR_ALREADY_EXISTS
					}

					return wintun, nil
				}
			}

			// This interface is not using Wintun driver.
			return nil, windows.ERROR_ALREADY_EXISTS
		}
	}

	return nil, windows.ERROR_OBJECT_NOT_FOUND
}

// CreateInterface creates a Wintun interface. ifname is the requested name of
// the interface, while requestedGUID is the GUID of the created network
// interface, which then influences NLA generation deterministically. If it is
// set to nil, the GUID is chosen by the system at random, and hence a new NLA
// entry is created for each new interface. It is called "requested" GUID
// because the API it uses is completely undocumented, and so there could be minor
// interesting complications with its usage. This function returns the network
// interface ID and a flag if reboot is required.
func (pool Pool) CreateInterface(ifname string, requestedGUID *windows.GUID) (wintun *Interface, rebootRequired bool, err error) {
	mutex, err := pool.takeNameMutex()
	if err != nil {
		return
	}
	defer func() {
		windows.ReleaseMutex(mutex)
		windows.CloseHandle(mutex)
	}()

	// Create an empty device info set for network adapter device class.
	devInfo, err := setupapi.SetupDiCreateDeviceInfoListEx(&deviceClassNetGUID, 0, "")
	if err != nil {
		err = fmt.Errorf("SetupDiCreateDeviceInfoListEx(%v) failed: %v", deviceClassNetGUID, err)
		return
	}
	defer devInfo.Close()

	// Get the device class name from GUID.
	className, err := setupapi.SetupDiClassNameFromGuidEx(&deviceClassNetGUID, "")
	if err != nil {
		err = fmt.Errorf("SetupDiClassNameFromGuidEx(%v) failed: %v", deviceClassNetGUID, err)
		return
	}

	// Create a new device info element and add it to the device info set.
	deviceTypeName := pool.deviceTypeName()
	devInfoData, err := devInfo.CreateDeviceInfo(className, &deviceClassNetGUID, deviceTypeName, 0, setupapi.DICD_GENERATE_ID)
	if err != nil {
		err = fmt.Errorf("SetupDiCreateDeviceInfo failed: %v", err)
		return
	}

	err = setQuietInstall(devInfo, devInfoData)
	if err != nil {
		err = fmt.Errorf("Setting quiet installation failed: %v", err)
		return
	}

	// Set a device information element as the selected member of a device information set.
	err = devInfo.SetSelectedDevice(devInfoData)
	if err != nil {
		err = fmt.Errorf("SetupDiSetSelectedDevice failed: %v", err)
		return
	}

	// Set Plug&Play device hardware ID property.
	err = devInfo.SetDeviceRegistryPropertyString(devInfoData, setupapi.SPDRP_HARDWAREID, hardwareID)
	if err != nil {
		err = fmt.Errorf("SetupDiSetDeviceRegistryProperty(SPDRP_HARDWAREID) failed: %v", err)
		return
	}

	err = devInfo.BuildDriverInfoList(devInfoData, setupapi.SPDIT_COMPATDRIVER) // TODO: This takes ~510ms
	if err != nil {
		err = fmt.Errorf("SetupDiBuildDriverInfoList failed: %v", err)
		return
	}
	defer devInfo.DestroyDriverInfoList(devInfoData, setupapi.SPDIT_COMPATDRIVER)

	driverDate := windows.Filetime{}
	driverVersion := uint64(0)
	for index := 0; ; index++ { // TODO: This loop takes ~600ms
		driverData, err := devInfo.EnumDriverInfo(devInfoData, setupapi.SPDIT_COMPATDRIVER, index)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for any driver versioned prior our best match.
		if driverData.IsNewer(driverDate, driverVersion) {
			driverDetailData, err := devInfo.DriverInfoDetail(devInfoData, driverData)
			if err != nil {
				continue
			}

			if driverDetailData.IsCompatible(hardwareID) {
				err := devInfo.SetSelectedDriver(devInfoData, driverData)
				if err != nil {
					continue
				}

				driverDate = driverData.DriverDate
				driverVersion = driverData.DriverVersion
			}
		}
	}

	if driverVersion == 0 {
		err = fmt.Errorf("No driver for device %q installed", hardwareID)
		return
	}

	defer func() {
		if err != nil {
			// The interface failed to install, or the interface ID was unobtainable. Clean-up.
			removeDeviceParams := setupapi.RemoveDeviceParams{
				ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
				Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
			}

			// Set class installer parameters for DIF_REMOVE.
			if devInfo.SetClassInstallParams(devInfoData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams))) == nil {
				// Call appropriate class installer.
				if devInfo.CallClassInstaller(setupapi.DIF_REMOVE, devInfoData) == nil {
					rebootRequired = rebootRequired || checkReboot(devInfo, devInfoData)
				}
			}

			wintun = nil
		}
	}()

	// Call appropriate class installer.
	err = devInfo.CallClassInstaller(setupapi.DIF_REGISTERDEVICE, devInfoData)
	if err != nil {
		err = fmt.Errorf("SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed: %v", err)
		return
	}

	// Register device co-installers if any. (Ignore errors)
	devInfo.CallClassInstaller(setupapi.DIF_REGISTER_COINSTALLERS, devInfoData)

	var netDevRegKey registry.Key
	const pollTimeout = time.Millisecond * 50
	for i := 0; i < int(waitForRegistryTimeout/pollTimeout); i++ {
		if i != 0 {
			time.Sleep(pollTimeout)
		}
		netDevRegKey, err = devInfo.OpenDevRegKey(devInfoData, setupapi.DICS_FLAG_GLOBAL, 0, setupapi.DIREG_DRV, registry.SET_VALUE|registry.QUERY_VALUE|registry.NOTIFY)
		if err == nil {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("SetupDiOpenDevRegKey failed: %v", err)
		return
	}
	defer netDevRegKey.Close()
	if requestedGUID != nil {
		err = netDevRegKey.SetStringValue("NetSetupAnticipatedInstanceId", requestedGUID.String())
		if err != nil {
			err = fmt.Errorf("SetStringValue(NetSetupAnticipatedInstanceId) failed: %v", err)
			return
		}
	}

	// Install interfaces if any. (Ignore errors)
	devInfo.CallClassInstaller(setupapi.DIF_INSTALLINTERFACES, devInfoData)

	// Install the device.
	err = devInfo.CallClassInstaller(setupapi.DIF_INSTALLDEVICE, devInfoData)
	if err != nil {
		err = fmt.Errorf("SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed: %v", err)
		return
	}
	rebootRequired = checkReboot(devInfo, devInfoData)

	err = devInfo.SetDeviceRegistryPropertyString(devInfoData, setupapi.SPDRP_DEVICEDESC, deviceTypeName)
	if err != nil {
		err = fmt.Errorf("SetDeviceRegistryPropertyString(SPDRP_DEVICEDESC) failed: %v", err)
		return
	}

	// DIF_INSTALLDEVICE returns almost immediately, while the device installation
	// continues in the background. It might take a while, before all registry
	// keys and values are populated.
	_, err = registryEx.GetStringValueWait(netDevRegKey, "NetCfgInstanceId", waitForRegistryTimeout)
	if err != nil {
		err = fmt.Errorf("GetStringValueWait(NetCfgInstanceId) failed: %v", err)
		return
	}
	_, err = registryEx.GetIntegerValueWait(netDevRegKey, "NetLuidIndex", waitForRegistryTimeout)
	if err != nil {
		err = fmt.Errorf("GetIntegerValueWait(NetLuidIndex) failed: %v", err)
		return
	}
	_, err = registryEx.GetIntegerValueWait(netDevRegKey, "*IfType", waitForRegistryTimeout)
	if err != nil {
		err = fmt.Errorf("GetIntegerValueWait(*IfType) failed: %v", err)
		return
	}

	// Get network interface.
	wintun, err = makeWintun(devInfo, devInfoData, pool)
	if err != nil {
		err = fmt.Errorf("makeWintun failed: %v", err)
		return
	}

	// Wait for TCP/IP adapter registry key to emerge and populate.
	tcpipAdapterRegKey, err := registryEx.OpenKeyWait(
		registry.LOCAL_MACHINE,
		wintun.tcpipAdapterRegKeyName(), registry.QUERY_VALUE|registry.NOTIFY,
		waitForRegistryTimeout)
	if err != nil {
		err = fmt.Errorf("OpenKeyWait(HKLM\\%s) failed: %v", wintun.tcpipAdapterRegKeyName(), err)
		return
	}
	defer tcpipAdapterRegKey.Close()
	_, err = registryEx.GetStringValueWait(tcpipAdapterRegKey, "IpConfig", waitForRegistryTimeout)
	if err != nil {
		err = fmt.Errorf("GetStringValueWait(IpConfig) failed: %v", err)
		return
	}

	tcpipInterfaceRegKeyName, err := wintun.tcpipInterfaceRegKeyName()
	if err != nil {
		err = fmt.Errorf("tcpipInterfaceRegKeyName failed: %v", err)
		return
	}

	// Wait for TCP/IP interface registry key to emerge.
	tcpipInterfaceRegKey, err := registryEx.OpenKeyWait(
		registry.LOCAL_MACHINE,
		tcpipInterfaceRegKeyName, registry.QUERY_VALUE|registry.SET_VALUE,
		waitForRegistryTimeout)
	if err != nil {
		err = fmt.Errorf("OpenKeyWait(HKLM\\%s) failed: %v", tcpipInterfaceRegKeyName, err)
		return
	}
	defer tcpipInterfaceRegKey.Close()
	// Disable dead gateway detection on our interface.
	tcpipInterfaceRegKey.SetDWordValue("EnableDeadGWDetect", 0)

	err = wintun.SetName(ifname)
	if err != nil {
		err = fmt.Errorf("Unable to set name of Wintun interface: %v", err)
		return
	}

	return
}

// DeleteInterface deletes a Wintun interface. This function succeeds
// if the interface was not found. It returns a bool indicating whether
// a reboot is required.
func (wintun *Interface) DeleteInterface() (rebootRequired bool, err error) {
	devInfo, devInfoData, err := wintun.devInfoData()
	if err == windows.ERROR_OBJECT_NOT_FOUND {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer devInfo.Close()

	// Remove the device.
	removeDeviceParams := setupapi.RemoveDeviceParams{
		ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
		Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
	}

	// Set class installer parameters for DIF_REMOVE.
	err = devInfo.SetClassInstallParams(devInfoData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams)))
	if err != nil {
		return false, fmt.Errorf("SetupDiSetClassInstallParams failed: %v", err)
	}

	// Call appropriate class installer.
	err = devInfo.CallClassInstaller(setupapi.DIF_REMOVE, devInfoData)
	if err != nil {
		return false, fmt.Errorf("SetupDiCallClassInstaller failed: %v", err)
	}

	return checkReboot(devInfo, devInfoData), nil
}

// DeleteMatchingInterfaces deletes all Wintun interfaces, which match
// given criteria, and returns which ones it deleted, whether a reboot
// is required after, and which errors occurred during the process.
func (pool Pool) DeleteMatchingInterfaces(matches func(wintun *Interface) bool) (deviceInstancesDeleted []uint32, rebootRequired bool, errors []error) {
	mutex, err := pool.takeNameMutex()
	if err != nil {
		errors = append(errors, err)
		return
	}
	defer func() {
		windows.ReleaseMutex(mutex)
		windows.CloseHandle(mutex)
	}()

	devInfo, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return nil, false, []error{fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err.Error())}
	}
	defer devInfo.Close()

	for i := 0; ; i++ {
		devInfoData, err := devInfo.EnumDeviceInfo(i)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Check the Hardware ID to make sure it's a real Wintun device first. This avoids doing slow operations on non-Wintun devices.
		property, err := devInfo.DeviceRegistryProperty(devInfoData, setupapi.SPDRP_HARDWAREID)
		if err != nil {
			continue
		}
		if hwids, ok := property.([]string); ok && len(hwids) > 0 && hwids[0] != hardwareID {
			continue
		}

		err = devInfo.BuildDriverInfoList(devInfoData, setupapi.SPDIT_COMPATDRIVER)
		if err != nil {
			continue
		}
		defer devInfo.DestroyDriverInfoList(devInfoData, setupapi.SPDIT_COMPATDRIVER)

		isWintun := false
		for j := 0; ; j++ {
			driverData, err := devInfo.EnumDriverInfo(devInfoData, setupapi.SPDIT_COMPATDRIVER, j)
			if err != nil {
				if err == windows.ERROR_NO_MORE_ITEMS {
					break
				}
				continue
			}
			driverDetailData, err := devInfo.DriverInfoDetail(devInfoData, driverData)
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

		isMember, err := pool.isMember(devInfo, devInfoData)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if !isMember {
			continue
		}

		wintun, err := makeWintun(devInfo, devInfoData, pool)
		if err != nil {
			errors = append(errors, fmt.Errorf("Unable to make Wintun interface object: %v", err))
			continue
		}
		if !matches(wintun) {
			continue
		}

		err = setQuietInstall(devInfo, devInfoData)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		inst := devInfoData.DevInst
		removeDeviceParams := setupapi.RemoveDeviceParams{
			ClassInstallHeader: *setupapi.MakeClassInstallHeader(setupapi.DIF_REMOVE),
			Scope:              setupapi.DI_REMOVEDEVICE_GLOBAL,
		}
		err = devInfo.SetClassInstallParams(devInfoData, &removeDeviceParams.ClassInstallHeader, uint32(unsafe.Sizeof(removeDeviceParams)))
		if err != nil {
			errors = append(errors, err)
			continue
		}
		err = devInfo.CallClassInstaller(setupapi.DIF_REMOVE, devInfoData)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		rebootRequired = rebootRequired || checkReboot(devInfo, devInfoData)
		deviceInstancesDeleted = append(deviceInstancesDeleted, inst)
	}
	return
}

// isMember checks if SPDRP_DEVICEDESC or SPDRP_FRIENDLYNAME match device type name.
func (pool Pool) isMember(devInfo setupapi.DevInfo, devInfoData *setupapi.DevInfoData) (bool, error) {
	deviceDescVal, err := devInfo.DeviceRegistryProperty(devInfoData, setupapi.SPDRP_DEVICEDESC)
	if err != nil {
		return false, fmt.Errorf("DeviceRegistryPropertyString(SPDRP_DEVICEDESC) failed: %v", err)
	}
	deviceDesc, _ := deviceDescVal.(string)
	friendlyNameVal, err := devInfo.DeviceRegistryProperty(devInfoData, setupapi.SPDRP_FRIENDLYNAME)
	if err != nil {
		return false, fmt.Errorf("DeviceRegistryPropertyString(SPDRP_FRIENDLYNAME) failed: %v", err)
	}
	friendlyName, _ := friendlyNameVal.(string)
	deviceTypeName := pool.deviceTypeName()
	return friendlyName == deviceTypeName || deviceDesc == deviceTypeName ||
		removeNumberedSuffix(friendlyName) == deviceTypeName || removeNumberedSuffix(deviceDesc) == deviceTypeName, nil
}

// checkReboot checks device install parameters if a system reboot is required.
func checkReboot(devInfo setupapi.DevInfo, devInfoData *setupapi.DevInfoData) bool {
	devInstallParams, err := devInfo.DeviceInstallParams(devInfoData)
	if err != nil {
		return false
	}

	return (devInstallParams.Flags & (setupapi.DI_NEEDREBOOT | setupapi.DI_NEEDRESTART)) != 0
}

// setQuietInstall sets device install parameters for a quiet installation
func setQuietInstall(devInfo setupapi.DevInfo, devInfoData *setupapi.DevInfoData) error {
	devInstallParams, err := devInfo.DeviceInstallParams(devInfoData)
	if err != nil {
		return err
	}

	devInstallParams.Flags |= setupapi.DI_QUIETINSTALL
	return devInfo.SetDeviceInstallParams(devInfoData, devInstallParams)
}

// deviceTypeName returns pool-specific device type name.
func (pool Pool) deviceTypeName() string {
	return fmt.Sprintf("%s Tunnel", pool)
}

// Name returns the name of the Wintun interface.
func (wintun *Interface) Name() (string, error) {
	return nci.ConnectionName(&wintun.cfgInstanceID)
}

// SetName sets name of the Wintun interface.
func (wintun *Interface) SetName(ifname string) error {
	const maxSuffix = 1000
	availableIfname := ifname
	for i := 0; ; i++ {
		err := nci.SetConnectionName(&wintun.cfgInstanceID, availableIfname)
		if err == windows.ERROR_DUP_NAME {
			duplicateGuid, err2 := iphlpapi.InterfaceGUIDFromAlias(availableIfname)
			if err2 == nil {
				for j := 0; j < maxSuffix; j++ {
					proposal := fmt.Sprintf("%s %d", ifname, j+1)
					if proposal == availableIfname {
						continue
					}
					err2 = nci.SetConnectionName(duplicateGuid, proposal)
					if err2 == windows.ERROR_DUP_NAME {
						continue
					}
					if err2 == nil {
						err = nci.SetConnectionName(&wintun.cfgInstanceID, availableIfname)
						if err == nil {
							break
						}
					}
					break
				}
			}
		}
		if err == nil {
			break
		}

		if i > maxSuffix || err != windows.ERROR_DUP_NAME {
			return fmt.Errorf("NciSetConnectionName failed: %v", err)
		}
		availableIfname = fmt.Sprintf("%s %d", ifname, i+1)
	}

	// TODO: This should use NetSetup2 so that it doesn't get unset.
	deviceRegKey, err := registry.OpenKey(registry.LOCAL_MACHINE, wintun.deviceRegKeyName(), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("Device-level registry key open failed: %v", err)
	}
	defer deviceRegKey.Close()
	err = deviceRegKey.SetStringValue("FriendlyName", wintun.pool.deviceTypeName())
	if err != nil {
		return fmt.Errorf("SetStringValue(FriendlyName) failed: %v", err)
	}
	return nil
}

// tcpipAdapterRegKeyName returns the adapter-specific TCP/IP network registry key name.
func (wintun *Interface) tcpipAdapterRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%v", wintun.cfgInstanceID)
}

// deviceRegKeyName returns the device-level registry key name.
func (wintun *Interface) deviceRegKeyName() string {
	return fmt.Sprintf("SYSTEM\\CurrentControlSet\\Enum\\%v", wintun.devInstanceID)
}

// Version returns the version of the Wintun driver and NDIS system currently loaded.
func (wintun *Interface) Version() (driverVersion string, ndisVersion string, err error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Wintun", registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	driverMajor, _, err := key.GetIntegerValue("DriverMajorVersion")
	if err != nil {
		return
	}
	driverMinor, _, err := key.GetIntegerValue("DriverMinorVersion")
	if err != nil {
		return
	}
	ndisMajor, _, err := key.GetIntegerValue("NdisMajorVersion")
	if err != nil {
		return
	}
	ndisMinor, _, err := key.GetIntegerValue("NdisMinorVersion")
	if err != nil {
		return
	}
	driverVersion = fmt.Sprintf("%d.%d", driverMajor, driverMinor)
	ndisVersion = fmt.Sprintf("%d.%d", ndisMajor, ndisMinor)
	return
}

// tcpipInterfaceRegKeyName returns the interface-specific TCP/IP network registry key name.
func (wintun *Interface) tcpipInterfaceRegKeyName() (path string, err error) {
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

// devInfoData returns TUN device info list handle and interface device info
// data. The device info list handle must be closed after use. In case the
// device is not found, windows.ERROR_OBJECT_NOT_FOUND is returned.
func (wintun *Interface) devInfoData() (setupapi.DevInfo, *setupapi.DevInfoData, error) {
	// Create a list of network devices.
	devInfo, err := setupapi.SetupDiGetClassDevsEx(&deviceClassNetGUID, "", 0, setupapi.DIGCF_PRESENT, setupapi.DevInfo(0), "")
	if err != nil {
		return 0, nil, fmt.Errorf("SetupDiGetClassDevsEx(%v) failed: %v", deviceClassNetGUID, err.Error())
	}

	for index := 0; ; index++ {
		devInfoData, err := devInfo.EnumDeviceInfo(index)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}

		// Get interface ID.
		// TODO: Store some ID in the Wintun object such that this call isn't required.
		wintun2, err := makeWintun(devInfo, devInfoData, wintun.pool)
		if err != nil {
			continue
		}

		if wintun.cfgInstanceID == wintun2.cfgInstanceID {
			err = setQuietInstall(devInfo, devInfoData)
			if err != nil {
				devInfo.Close()
				return 0, nil, fmt.Errorf("Setting quiet installation failed: %v", err)
			}
			return devInfo, devInfoData, nil
		}
	}

	devInfo.Close()
	return 0, nil, windows.ERROR_OBJECT_NOT_FOUND
}

// handle returns a handle to the interface device object.
func (wintun *Interface) handle() (windows.Handle, error) {
	interfaces, err := setupapi.CM_Get_Device_Interface_List(wintun.devInstanceID, &deviceInterfaceNetGUID, setupapi.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("Error listing NDIS interfaces: %v", err)
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(interfaces[0]), windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("Error opening NDIS device: %v", err)
	}
	return handle, nil
}

// GUID returns the GUID of the interface.
func (wintun *Interface) GUID() windows.GUID {
	return wintun.cfgInstanceID
}

// LUID returns the LUID of the interface.
func (wintun *Interface) LUID() uint64 {
	return ((uint64(wintun.luidIndex) & ((1 << 24) - 1)) << 24) | ((uint64(wintun.ifType) & ((1 << 16) - 1)) << 48)
}
