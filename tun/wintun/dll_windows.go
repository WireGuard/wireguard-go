/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun/memmod"
	"golang.zx2c4.com/wireguard/tun/wintun/resource"
)

type lazyDLL struct {
	Name   string
	mu     sync.Mutex
	module *memmod.Module
}

func newLazyDLL(name string) *lazyDLL {
	return &lazyDLL{Name: name}
}

func (d *lazyDLL) Load() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module != nil {
		return nil
	}

	const ourModule windows.Handle = 0
	resInfo, err := resource.FindByName(ourModule, d.Name, resource.RT_RCDATA)
	if err != nil {
		return fmt.Errorf("Unable to find \"%v\" RCDATA resource: %v", d.Name, err)
	}
	data, err := resource.Load(ourModule, resInfo)
	if err != nil {
		return fmt.Errorf("Unable to load resource: %v", err)
	}
	module, err := memmod.LoadLibrary(data)
	if err != nil {
		return fmt.Errorf("Unable to load library: %v", err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))
	return nil
}

func (d *lazyDLL) NewProc(name string) *lazyProc {
	return &lazyProc{dll: d, Name: name}
}

type lazyProc struct {
	Name string
	mu   sync.Mutex
	dll  *lazyDLL
	addr uintptr
}

func (p *lazyProc) Find() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr))) != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr != 0 {
		return nil
	}

	err := p.dll.Load()
	if err != nil {
		return fmt.Errorf("Error loading %v DLL: %v", p.dll.Name, err)
	}
	addr, err := p.dll.module.ProcAddressByName(p.Name)
	if err != nil {
		return fmt.Errorf("Error getting %v address: %v", p.Name, err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr)), unsafe.Pointer(addr))
	return nil
}

func (p *lazyProc) Addr() uintptr {
	err := p.Find()
	if err != nil {
		panic(err)
	}
	return p.addr
}
