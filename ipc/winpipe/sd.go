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

//sys	convertStringSecurityDescriptorToSecurityDescriptor(str string, revision uint32, sd *uintptr, size *uint32) (err error) = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
//sys	localFree(mem uintptr) = LocalFree
//sys	getSecurityDescriptorLength(sd uintptr) (len uint32) = advapi32.GetSecurityDescriptorLength
//sys	getSecurityInfo(handle syscall.Handle, objectType uint32, securityInformation uint32, owner **syscall.SID, group **syscall.SID, dacl *uintptr, sacl *uintptr, sd *uintptr) (ret error) = advapi32.GetSecurityInfo
//sys	equalSid(sid1 *syscall.SID, sid2 *syscall.SID) (isEqual bool) = advapi32.EqualSid

const (
	SE_FILE_OBJECT             = 1
	OWNER_SECURITY_INFORMATION = 1
)

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
