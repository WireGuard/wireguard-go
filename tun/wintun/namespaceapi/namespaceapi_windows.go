/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package namespaceapi

import "golang.org/x/sys/windows"

//sys	createBoundaryDescriptor(name *uint16, flags uint32) (handle windows.Handle, err error) = kernel32.CreateBoundaryDescriptorW
//sys	deleteBoundaryDescriptor(boundaryDescriptor windows.Handle) = kernel32.DeleteBoundaryDescriptor
//sys	addSIDToBoundaryDescriptor(boundaryDescriptor *windows.Handle, requiredSid *windows.SID) (err error) = kernel32.AddSIDToBoundaryDescriptor
//sys	createPrivateNamespace(privateNamespaceAttributes *windows.SecurityAttributes, boundaryDescriptor windows.Handle, aliasPrefix *uint16) (handle windows.Handle, err error) = kernel32.CreatePrivateNamespaceW
//sys	openPrivateNamespace(boundaryDescriptor windows.Handle, aliasPrefix *uint16) (handle windows.Handle, err error) = kernel32.OpenPrivateNamespaceW
//sys	closePrivateNamespace(handle windows.Handle, flags uint32) (err error) = kernel32.ClosePrivateNamespace

// BoundaryDescriptor represents a boundary that defines how the objects in the namespace are to be isolated.
type BoundaryDescriptor windows.Handle

// CreateBoundaryDescriptor creates a boundary descriptor.
func CreateBoundaryDescriptor(name string) (BoundaryDescriptor, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	handle, err := createBoundaryDescriptor(name16, 0)
	if err != nil {
		return 0, err
	}
	return BoundaryDescriptor(handle), nil
}

// Delete deletes the specified boundary descriptor.
func (bd BoundaryDescriptor) Delete() {
	deleteBoundaryDescriptor(windows.Handle(bd))
}

// AddSid adds a security identifier (SID) to the specified boundary descriptor.
func (bd *BoundaryDescriptor) AddSid(requiredSid *windows.SID) error {
	return addSIDToBoundaryDescriptor((*windows.Handle)(bd), requiredSid)
}

// PrivateNamespace represents a private namespace.
type PrivateNamespace windows.Handle

// CreatePrivateNamespace creates a private namespace.
func CreatePrivateNamespace(privateNamespaceAttributes *windows.SecurityAttributes, boundaryDescriptor BoundaryDescriptor, aliasPrefix string) (PrivateNamespace, error) {
	aliasPrefix16, err := windows.UTF16PtrFromString(aliasPrefix)
	if err != nil {
		return 0, err
	}
	handle, err := createPrivateNamespace(privateNamespaceAttributes, windows.Handle(boundaryDescriptor), aliasPrefix16)
	if err != nil {
		return 0, err
	}
	return PrivateNamespace(handle), nil
}

// OpenPrivateNamespace opens a private namespace.
func OpenPrivateNamespace(boundaryDescriptor BoundaryDescriptor, aliasPrefix string) (PrivateNamespace, error) {
	aliasPrefix16, err := windows.UTF16PtrFromString(aliasPrefix)
	if err != nil {
		return 0, err
	}
	handle, err := openPrivateNamespace(windows.Handle(boundaryDescriptor), aliasPrefix16)
	if err != nil {
		return 0, err
	}
	return PrivateNamespace(handle), nil
}

// ClosePrivateNamespaceFlags describes flags that are used by PrivateNamespace's Close() method.
type ClosePrivateNamespaceFlags uint32

const (
	// PrivateNamespaceFlagDestroy makes the close to destroy the namespace.
	PrivateNamespaceFlagDestroy = ClosePrivateNamespaceFlags(0x1)
)

// Close closes an open namespace handle.
func (pns PrivateNamespace) Close(flags ClosePrivateNamespaceFlags) error {
	return closePrivateNamespace(windows.Handle(pns), uint32(flags))
}
