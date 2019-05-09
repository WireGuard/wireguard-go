/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package registry

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	KEY_NOTIFY uint32 = 0x0010 // should be defined upstream as registry.KEY_NOTIFY
)

const (
	// REG_NOTIFY_CHANGE_NAME notifies the caller if a subkey is added or deleted.
	REG_NOTIFY_CHANGE_NAME uint32 = 0x00000001

	// REG_NOTIFY_CHANGE_ATTRIBUTES notifies the caller of changes to the attributes of the key, such as the security descriptor information.
	REG_NOTIFY_CHANGE_ATTRIBUTES uint32 = 0x00000002

	// REG_NOTIFY_CHANGE_LAST_SET notifies the caller of changes to a value of the key. This can include adding or deleting a value, or changing an existing value.
	REG_NOTIFY_CHANGE_LAST_SET uint32 = 0x00000004

	// REG_NOTIFY_CHANGE_SECURITY notifies the caller of changes to the security descriptor of the key.
	REG_NOTIFY_CHANGE_SECURITY uint32 = 0x00000008

	// REG_NOTIFY_THREAD_AGNOSTIC indicates that the lifetime of the registration must not be tied to the lifetime of the thread issuing the RegNotifyChangeKeyValue call. Note: This flag value is only supported in Windows 8 and later.
	REG_NOTIFY_THREAD_AGNOSTIC uint32 = 0x10000000
)

//sys	regNotifyChangeKeyValue(key windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) (regerrno error) = advapi32.RegNotifyChangeKeyValue

func OpenKeyWait(k registry.Key, path string, access uint32, timeout time.Duration) (registry.Key, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	deadline := time.Now().Add(timeout)
	pathSpl := strings.Split(path, "\\")
	for i := 0; ; i++ {
		keyName := pathSpl[i]
		isLast := i+1 == len(pathSpl)

		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return 0, fmt.Errorf("Error creating event: %v", err)
		}
		defer windows.CloseHandle(event)

		var key registry.Key
		for {
			err = regNotifyChangeKeyValue(windows.Handle(k), false, REG_NOTIFY_CHANGE_NAME, windows.Handle(event), true)
			if err != nil {
				return 0, fmt.Errorf("Setting up change notification on registry key failed: %v", err)
			}

			var accessFlags uint32
			if isLast {
				accessFlags = access
			} else {
				accessFlags = KEY_NOTIFY
			}
			key, err = registry.OpenKey(k, keyName, accessFlags)
			if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
				timeout := time.Until(deadline) / time.Millisecond
				if timeout < 0 {
					timeout = 0
				}
				s, err := windows.WaitForSingleObject(event, uint32(timeout))
				if err != nil {
					return 0, fmt.Errorf("Unable to wait on registry key: %v", err)
				}
				if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
					return 0, errors.New("Timeout waiting for registry key")
				}
			} else if err != nil {
				return 0, fmt.Errorf("Error opening registry key %v: %v", path, err)
			} else {
				if isLast {
					return key, nil
				}
				defer key.Close()
				break
			}
		}

		k = key
	}
}

func WaitForKey(k registry.Key, path string, timeout time.Duration) error {
	key, err := OpenKeyWait(k, path, KEY_NOTIFY, timeout)
	if err != nil {
		return err
	}
	key.Close()
	return nil
}

//
// getStringValueRetry function reads a string value from registry. It waits for
// the registry value to become available or returns error on timeout.
//
// Key must be opened with at least QUERY_VALUE|KEY_NOTIFY access.
//
func getStringValueRetry(key registry.Key, name string, timeout time.Duration) (string, uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return "", 0, fmt.Errorf("Error creating event: %v", err)
	}
	defer windows.CloseHandle(event)

	deadline := time.Now().Add(timeout)
	for {
		err := regNotifyChangeKeyValue(windows.Handle(key), false, REG_NOTIFY_CHANGE_LAST_SET, windows.Handle(event), true)
		if err != nil {
			return "", 0, fmt.Errorf("Setting up change notification on registry value failed: %v", err)
		}

		value, valueType, err := key.GetStringValue(name)
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			timeout := time.Until(deadline) / time.Millisecond
			if timeout < 0 {
				timeout = 0
			}
			s, err := windows.WaitForSingleObject(event, uint32(timeout))
			if err != nil {
				return "", 0, fmt.Errorf("Unable to wait on registry value: %v", err)
			}
			if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
				return "", 0, errors.New("Timeout waiting for registry value")
			}
		} else if err != nil {
			return "", 0, fmt.Errorf("Error reading registry value %v: %v", name, err)
		} else {
			return value, valueType, nil
		}
	}
}

func expandString(value string, valueType uint32, err error) (string, error) {
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
// GetStringValueWait function reads a string value from registry. It waits
// for the registry value to become available or returns error on timeout.
//
// Key must be opened with at least QUERY_VALUE|KEY_NOTIFY access.
//
// If the value type is REG_EXPAND_SZ the environment variables are expanded.
// Should expanding fail, original string value and nil error are returned.
//
func GetStringValueWait(key registry.Key, name string, timeout time.Duration) (string, error) {
	return expandString(getStringValueRetry(key, name, timeout))
}

//
// GetStringValue function reads a string value from registry.
//
// Key must be opened with at least QUERY_VALUE access.
//
// If the value type is REG_EXPAND_SZ the environment variables are expanded.
// Should expanding fail, original string value and nil error are returned.
//
func GetStringValue(key registry.Key, name string) (string, error) {
	return expandString(key.GetStringValue(name))
}

//
// GetIntegerValueWait function reads a DWORD32 or QWORD value from registry.
// It waits for the registry value to become available or returns error on
// timeout.
//
// Key must be opened with at least QUERY_VALUE|KEY_NOTIFY access.
//
func GetIntegerValueWait(key registry.Key, name string, timeout time.Duration) (uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("Error creating event: %v", err)
	}
	defer windows.CloseHandle(event)

	deadline := time.Now().Add(timeout)
	for {
		err := regNotifyChangeKeyValue(windows.Handle(key), false, REG_NOTIFY_CHANGE_LAST_SET, windows.Handle(event), true)
		if err != nil {
			return 0, fmt.Errorf("Setting up change notification on registry value failed: %v", err)
		}

		value, _, err := key.GetIntegerValue(name)
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			timeout := time.Until(deadline) / time.Millisecond
			if timeout < 0 {
				timeout = 0
			}
			s, err := windows.WaitForSingleObject(event, uint32(timeout))
			if err != nil {
				return 0, fmt.Errorf("Unable to wait on registry value: %v", err)
			}
			if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
				return 0, errors.New("Timeout waiting for registry value")
			}
		} else if err != nil {
			return 0, fmt.Errorf("Error reading registry value %v: %v", name, err)
		} else {
			return value, nil
		}
	}
}
