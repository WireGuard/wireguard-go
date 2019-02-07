/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output ztun_windows.go tun_windows.go

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"git.zx2c4.com/wireguard-go/setupapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TUN_MAX_PACKET_SIZE      = 1600
	TUN_MAX_PACKET_EXCHANGE  = 256 // Number of packets that can be exchanged at a time
	TUN_EXCHANGE_BUFFER_SIZE = 410632
)

const (
	TUN_SIGNAL_DATA_AVAIL = 0
	TUN_SIGNAL_CLOSE      = 1

	TUN_SIGNAL_MAX = 2
)

var deviceClassNetGUID = windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

const TUN_HWID = "Wintun"

type tunPacket struct {
	size uint32
	data [TUN_MAX_PACKET_SIZE]byte
}

type tunRWQueue struct {
	numPackets uint32
	packets    [TUN_MAX_PACKET_EXCHANGE]tunPacket
	left       uint32
}

type nativeTun struct {
	ifid         *windows.GUID
	tunName      string
	signalName   *uint16
	tunFile      *os.File
	wrBuff       tunRWQueue
	rdBuff       tunRWQueue
	signals      [TUN_SIGNAL_MAX]windows.Handle
	rdNextPacket uint32
	events       chan TUNEvent
	errors       chan error
}

func CreateTUN(ifname string) (TUNDevice, error) {
	// Does an interface with this name already exist?
	ifid, err := getInterface(ifname, 0)
	if ifid == nil || err != nil {
		// Interface does not exist or an error occured. Create one.
		ifid, _, err = createInterface("WireGuard Tunnel Adapter", 0)
		if err != nil {
			return nil, err
		}

		// Set interface name. (Ignore errors.)
		setInterfaceName(ifid, ifname)
	}

	ifidStr := guidToString(ifid)

	signalNameUTF16, err := windows.UTF16PtrFromString(fmt.Sprintf("Global\\WINTUN_EVENT_%s", ifidStr))
	if err != nil {
		deleteInterface(ifid, 0)
		return nil, err
	}

	// Create instance.
	tun := &nativeTun{
		ifid:       ifid,
		tunName:    fmt.Sprintf("\\\\.\\Global\\WINTUN_DEVICE_%s", ifidStr),
		signalName: signalNameUTF16,
		events:     make(chan TUNEvent, 10),
		errors:     make(chan error, 1),
	}

	// Create close event.
	tun.signals[TUN_SIGNAL_CLOSE], err = windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
	if err != nil {
		deleteInterface(ifid, 0)
		return nil, err
	}

	return tun, nil
}

func (tun *nativeTun) openTUN() error {
	for {
		// Open interface data pipe.
		// Data pipe must be opened first, as the interface data available event is created when somebody actually connects to the data pipe.
		file, err := os.OpenFile(tun.tunName, os.O_RDWR|os.O_SYNC, 0600)
		if err != nil {
			// After examining possible error conditions, many arose that were only temporary: windows.ERROR_FILE_NOT_FOUND, "read <filename> closed", etc.
			// To simplify, we will enter a retry-loop on _any_ error until session is closed by user.
			switch evt, e := windows.WaitForSingleObject(tun.signals[TUN_SIGNAL_CLOSE], 1000); evt {
			case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
				return errors.New("TUN closed")
			case windows.WAIT_TIMEOUT:
				continue
			default:
				return errors.New("Unexpected result from WaitForSingleObject: " + e.Error())
			}
		}

		// Open interface data available event.
		event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, tun.signalName)
		if err != nil {
			file.Close()
			return errors.New("Opening interface data ready event failed: " + err.Error())
		}

		tun.tunFile = file
		tun.signals[TUN_SIGNAL_DATA_AVAIL] = event

		return nil
	}
}

func (tun *nativeTun) closeTUN() (err error) {
	if tun.signals[TUN_SIGNAL_DATA_AVAIL] != 0 {
		// Close interface data ready event.
		e := windows.CloseHandle(tun.signals[TUN_SIGNAL_DATA_AVAIL])
		if err != nil {
			err = e
		}

		tun.signals[TUN_SIGNAL_DATA_AVAIL] = 0
	}

	if tun.tunFile != nil {
		// Close interface data pipe.
		e := tun.tunFile.Close()
		if err != nil {
			err = e
		}

		tun.tunFile = nil
	}

	return
}

func (tun *nativeTun) Name() (string, error) {
	return getInterfaceName(tun.ifid)
}

func (tun *nativeTun) File() *os.File {
	return nil
}

func (tun *nativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *nativeTun) Close() error {
	windows.SetEvent(tun.signals[TUN_SIGNAL_CLOSE])
	err := windows.CloseHandle(tun.signals[TUN_SIGNAL_CLOSE])

	e := tun.closeTUN()
	if err == nil {
		err = e
	}

	if tun.events != nil {
		close(tun.events)
	}

	_, _, e = deleteInterface(tun.ifid, 0)
	if err == nil {
		err = e
	}

	return err
}

func (tun *nativeTun) MTU() (int, error) {
	return 1500, nil
}

func (tun *nativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err

	default:
		for {
			if tun.rdNextPacket < tun.rdBuff.numPackets {
				// Get packet from the queue.
				tunPacket := &tun.rdBuff.packets[tun.rdNextPacket]
				tun.rdNextPacket++

				if TUN_MAX_PACKET_SIZE < tunPacket.size {
					// Invalid packet size.
					continue
				}

				// Copy data.
				copy(buff[offset:], tunPacket.data[:tunPacket.size])
				return int(tunPacket.size), nil
			}

			if tun.signals[TUN_SIGNAL_DATA_AVAIL] == 0 {
				// Data pipe and interface data available event are not open (yet).
				err := tun.openTUN()
				if err != nil {
					return 0, err
				}
			}

			if tun.rdBuff.numPackets < TUN_MAX_PACKET_EXCHANGE || tun.rdBuff.left == 0 {
				// Buffer was not full. Wait for the interface data or user close.
				r, err := windows.WaitForMultipleObjects(tun.signals[:], false, windows.INFINITE)
				if err != nil {
					return 0, errors.New("Waiting for data failed: " + err.Error())
				}
				switch r {
				case windows.WAIT_OBJECT_0 + TUN_SIGNAL_DATA_AVAIL:
					// Data is available.
				case windows.WAIT_ABANDONED + TUN_SIGNAL_DATA_AVAIL:
					// TUN stopped. Reopen it.
					tun.closeTUN()
					continue
				case windows.WAIT_OBJECT_0 + TUN_SIGNAL_CLOSE, windows.WAIT_ABANDONED + TUN_SIGNAL_CLOSE:
					return 0, errors.New("TUN closed")
				case windows.WAIT_TIMEOUT:
					// Congratulations, we reached infinity. Let's do it again! :)
					continue
				default:
					return 0, errors.New("unexpected result from WaitForMultipleObjects")
				}
			}

			// Fill queue.
			data := (*[TUN_EXCHANGE_BUFFER_SIZE]byte)(unsafe.Pointer(&tun.rdBuff))
			n, err := tun.tunFile.Read(data[:])
			tun.rdNextPacket = 0
			if n != TUN_EXCHANGE_BUFFER_SIZE || err != nil {
				// TUN interface stopped, returned incomplete data, etc.
				// Retry.
				tun.rdBuff.numPackets = 0
				tun.closeTUN()
				continue
			}
		}
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *nativeTun) flush() error {
	// Flush write buffer.
	data := (*[TUN_EXCHANGE_BUFFER_SIZE]byte)(unsafe.Pointer(&tun.wrBuff))
	n, err := tun.tunFile.Write(data[:])
	tun.wrBuff.numPackets = 0
	if err != nil {
		return err
	}
	if n != TUN_EXCHANGE_BUFFER_SIZE {
		return fmt.Errorf("%d byte(s) written, %d byte(s) expected", n, TUN_EXCHANGE_BUFFER_SIZE)
	}

	return nil
}

func (tun *nativeTun) putTunPacket(buff []byte) error {
	size := len(buff)
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > TUN_MAX_PACKET_SIZE {
		return errors.New("Packet too big")
	}

	if tun.wrBuff.numPackets >= TUN_MAX_PACKET_EXCHANGE {
		// Queue is full -> flush first.
		err := tun.flush()
		if err != nil {
			return err
		}
	}

	// Push packet to the buffer.
	tunPacket := &tun.wrBuff.packets[tun.wrBuff.numPackets]
	tunPacket.size = uint32(size)
	copy(tunPacket.data[:size], buff)

	tun.wrBuff.numPackets++

	return nil
}

func (tun *nativeTun) Write(buff []byte, offset int) (int, error) {
	err := tun.putTunPacket(buff[offset:])
	if err != nil {
		return 0, err
	}

	// Flush write buffer.
	return len(buff) - offset, tun.flush()
}

//
// getInterface finds interface ID by name.
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
func getInterface(ifname string, hwndParent uintptr) (*windows.GUID, error) {
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
		ifname2, err := getInterfaceName(ifid)
		if err != nil {
			// Something is wrong with this device. Skip it.
			continue
		}

		if ifname == strings.ToLower(ifname2) {
			// Interface name found.
			return ifid, nil
		}
	}

	return nil, nil
}

//
// createInterface creates a TUN interface.
//
// description is a string that supplies the text description of the device.
// Description is optional and can be "".
//
// hwndParent is a handle to the top-level window to use for any user
// interface that is related to non-device-specific actions (such as a select-
// device dialog box that uses the global class driver list). This handle is
// optional and can be 0. If a specific top-level window is not required, set
// hwndParent to 0.
//
// Function returns the network interface ID and a flag if reboot is required.
//
func createInterface(description string, hwndParent uintptr) (*windows.GUID, bool, error) {
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
		return ifid, rebootRequired, nil
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
// deleteInterface deletes a TUN interface.
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
func deleteInterface(ifid *windows.GUID, hwndParent uintptr) (bool, bool, error) {
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

		if ifid == ifid2 {
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
		ifid, err := stringToGUID(value)
		if err != nil {
			return nil, fmt.Errorf("NetCfgInstanceId registry value is not a GUID (expected: \"{...}\", provided: \"%v\")", value)
		}

		return ifid, err
	}
}

//
// getInterfaceName returns network interface name.
//
func getInterfaceName(ifid *windows.GUID) (string, error) {
	// Open network interface registry key.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guidToString(&deviceClassNetGUID), guidToString(ifid)), registry.QUERY_VALUE)
	if err != nil {
		return "", errors.New("Network-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	// Get the interface name.
	return getRegStringValue(key, "Name")
}

//
// setInterfaceName sets network interface name.
//
func setInterfaceName(ifid *windows.GUID, ifname string) error {
	// Open network interface registry key.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Control\\Network\\%v\\%v\\Connection", guidToString(&deviceClassNetGUID), guidToString(ifid)), registry.SET_VALUE)
	if err != nil {
		return errors.New("Network-specific registry key open failed: " + err.Error())
	}
	defer key.Close()

	// Set the interface name.
	return key.SetStringValue("Name", ifname)
}

//sys	clsidFromString(lpsz *uint16, pclsid *windows.GUID) (hr int32) = ole32.CLSIDFromString

//
// stringToGUID parses "{XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" string to GUID.
//
func stringToGUID(str string) (*windows.GUID, error) {
	strUTF16, err := syscall.UTF16PtrFromString(str)
	if err != nil {
		return nil, err
	}

	guid := &windows.GUID{}

	hr := clsidFromString(strUTF16, guid)
	if hr < 0 {
		return nil, syscall.Errno(hr)
	}

	return guid, nil
}

//
// guidToString function converts GUID to string
// "{XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
//
// The resulting string is uppercase.
//
func guidToString(guid *windows.GUID) string {
	return fmt.Sprintf("{%06X-%04X-%04X-%04X-%012X}", guid.Data1, guid.Data2, guid.Data3, guid.Data4[:2], guid.Data4[2:])
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
