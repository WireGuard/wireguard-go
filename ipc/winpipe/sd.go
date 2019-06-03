// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2005 Microsoft
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package winpipe

import (
	"unsafe"
)

//sys convertStringSecurityDescriptorToSecurityDescriptor(str string, revision uint32, sd *uintptr, size *uint32) (err error) = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
//sys localFree(mem uintptr) = LocalFree
//sys getSecurityDescriptorLength(sd uintptr) (len uint32) = advapi32.GetSecurityDescriptorLength

func SddlToSecurityDescriptor(sddl string) ([]byte, error) {
	var sdBuffer uintptr
	err := convertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, &sdBuffer, nil)
	if err != nil {
		return nil, err
	}
	defer localFree(sdBuffer)
	sd := make([]byte, getSecurityDescriptorLength(sdBuffer))
	copy(sd, (*[0xffff]byte)(unsafe.Pointer(sdBuffer))[:len(sd)])
	return sd, nil
}
