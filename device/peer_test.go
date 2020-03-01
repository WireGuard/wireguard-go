/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"reflect"
	"testing"
	"unsafe"
)

func checkAlignment(t *testing.T, name string, offset uintptr) {
	t.Helper()
	if offset%8 != 0 {
		t.Errorf("offset of %q within struct is %d bytes, which does not align to 64-bit word boundaries (missing %d bytes). Atomic operations will crash on 32-bit systems.", name, offset, 8-(offset%8))
	}
}

// TestPeerAlignment checks that atomically-accessed fields are
// aligned to 64-bit boundaries, as required by the atomic package.
//
// Unfortunately, violating this rule on 32-bit platforms results in a
// hard segfault at runtime.
func TestPeerAlignment(t *testing.T) {
	var p Peer

	typ := reflect.TypeOf(p)
	t.Logf("Peer type size: %d, with fields:", typ.Size())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Logf("\t%30s\toffset=%3v\t(type size=%3d, align=%d)",
			field.Name,
			field.Offset,
			field.Type.Size(),
			field.Type.Align(),
		)
	}

	checkAlignment(t, "Peer.stats", unsafe.Offsetof(p.stats))
	checkAlignment(t, "Peer.isRunning", unsafe.Offsetof(p.isRunning))
}
