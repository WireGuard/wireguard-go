/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package iphlpapi

import "golang.org/x/sys/windows"

//sys	convertInterfaceLUIDToGUID(interfaceLUID *uint64, interfaceGUID *windows.GUID) (ret error) = iphlpapi.ConvertInterfaceLuidToGuid
//sys	convertInterfaceAliasToLUID(interfaceAlias *uint16, interfaceLUID *uint64) (ret error) = iphlpapi.ConvertInterfaceAliasToLuid

func InterfaceGUIDFromAlias(alias string) (*windows.GUID, error) {
	var luid uint64
	var guid windows.GUID
	err := convertInterfaceAliasToLUID(windows.StringToUTF16Ptr(alias), &luid)
	if err != nil {
		return nil, err
	}
	err = convertInterfaceLUIDToGUID(&luid, &guid)
	if err != nil {
		return nil, err
	}
	return &guid, nil
}
