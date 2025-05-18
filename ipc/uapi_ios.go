/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"os"
	"strings"
)

func init() {
	// in iOS there is no access to write into */var/run* directory
	// but we can use app specific temp directory instead
	socketDirectory = strings.TrimSuffix(os.TempDir(), string(os.PathSeparator))
}
