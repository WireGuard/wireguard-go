/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package nci

import "golang.org/x/sys/windows"

//sys	nciSetConnectionName(guid *windows.GUID, newName *uint16) (ret error) = nci.NciSetConnectionName
//sys	nciGetConnectionName(guid *windows.GUID, destName *uint16, inDestNameBytes uint32, outDestNameBytes *uint32) (ret error) = nci.NciGetConnectionName

func SetConnectionName(guid *windows.GUID, newName string) error {
	newName16, err := windows.UTF16PtrFromString(newName)
	if err != nil {
		return err
	}
	return nciSetConnectionName(guid, newName16)
}

func ConnectionName(guid *windows.GUID) (string, error) {
	var name [0x400]uint16
	err := nciGetConnectionName(guid, &name[0], uint32(len(name)*2), nil)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(name[:]), nil
}
