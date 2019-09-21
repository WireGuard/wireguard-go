/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/sys/windows"
	"golang.org/x/text/unicode/norm"

	"golang.zx2c4.com/wireguard/tun/wintun/namespaceapi"
)

var (
	wintunObjectSecurityAttributes *windows.SecurityAttributes
	hasInitializedNamespace        bool
	initializingNamespace          sync.Mutex
)

func initializeNamespace() error {
	initializingNamespace.Lock()
	defer initializingNamespace.Unlock()
	if hasInitializedNamespace {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)")
	if err != nil {
		return fmt.Errorf("SddlToSecurityDescriptor failed: %v", err)
	}
	wintunObjectSecurityAttributes = &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	sid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid(LOCAL_SYSTEM) failed: %v", err)
	}

	boundary, err := namespaceapi.CreateBoundaryDescriptor("Wintun")
	if err != nil {
		return fmt.Errorf("CreateBoundaryDescriptor failed: %v", err)
	}
	err = boundary.AddSid(sid)
	if err != nil {
		return fmt.Errorf("AddSIDToBoundaryDescriptor failed: %v", err)
	}
	for {
		_, err = namespaceapi.CreatePrivateNamespace(wintunObjectSecurityAttributes, boundary, "Wintun")
		if err == windows.ERROR_ALREADY_EXISTS {
			_, err = namespaceapi.OpenPrivateNamespace(boundary, "Wintun")
			if err == windows.ERROR_PATH_NOT_FOUND {
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("Create/OpenPrivateNamespace failed: %v", err)
		}
		break
	}
	hasInitializedNamespace = true
	return nil
}

func (pool Pool) takeNameMutex() (windows.Handle, error) {
	err := initializeNamespace()
	if err != nil {
		return 0, err
	}

	const mutexLabel = "WireGuard Adapter Name Mutex Stable Suffix v1 jason@zx2c4.com"
	b2, _ := blake2s.New256(nil)
	b2.Write([]byte(mutexLabel))
	b2.Write(norm.NFC.Bytes([]byte(string(pool))))
	mutexName := `Wintun\Wintun-Name-Mutex-` + hex.EncodeToString(b2.Sum(nil))
	mutex, err := windows.CreateMutex(wintunObjectSecurityAttributes, false, windows.StringToUTF16Ptr(mutexName))
	if err != nil {
		err = fmt.Errorf("Error creating name mutex: %v", err)
		return 0, err
	}
	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		windows.CloseHandle(mutex)
		return 0, fmt.Errorf("Error waiting on name mutex: %v", err)
	}
	if event != windows.WAIT_OBJECT_0 && event != windows.WAIT_ABANDONED {
		windows.CloseHandle(mutex)
		return 0, errors.New("Error with event trigger of name mutex")
	}
	return mutex, nil
}
