/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"golang.org/x/sys/windows/registry"
	"time"
)

const (
	numRetries = 25
	retryTimeout = 100 * time.Millisecond
)

func registryOpenKeyRetry(k registry.Key, path string, access uint32) (key registry.Key, err error) {
	for i := 0; i < numRetries; i++ {
		key, err = registry.OpenKey(k, path, access)
		if err == nil {
			break
		}
		if i != numRetries - 1 {
			time.Sleep(retryTimeout)
		}
	}
	return
}

func keyGetStringValueRetry(k registry.Key, name string) (val string, valtype uint32, err error) {
	for i := 0; i < numRetries; i++ {
		val, valtype, err = k.GetStringValue(name)
		if err == nil {
			break
		}
		if i != numRetries - 1 {
			time.Sleep(retryTimeout)
		}
	}
	return
}
