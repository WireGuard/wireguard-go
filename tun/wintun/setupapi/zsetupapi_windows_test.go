/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package setupapi

import (
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetupDiDestroyDeviceInfoList(t *testing.T) {
	err := SetupDiDestroyDeviceInfoList(DevInfo(windows.InvalidHandle))
	if errWin, ok := err.(syscall.Errno); !ok || errWin != windows.ERROR_INVALID_HANDLE {
		t.Errorf("SetupDiDestroyDeviceInfoList(nil, ...) should fail with ERROR_INVALID_HANDLE")
	}
}
