/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2018 Mathias N. Hall-Andersen <mathias@hall-andersen.dk>.
 */

package main

/* UAPI on windows uses a bidirectional named pipe
 */

import (
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
)

const (
	ipcErrorIO        = -int64(windows.ERROR_BROKEN_PIPE)
	ipcErrorProtocol  = -int64(windows.ERROR_INVALID_NAME)
	ipcErrorInvalid   = -int64(windows.ERROR_INVALID_PARAMETER)
	ipcErrorPortInUse = -int64(windows.ERROR_ALREADY_EXISTS)
)

const PipeNameFmt = "\\\\.\\pipe\\wireguard-ipc-%s"

type UAPIListener struct {
	listener net.Listener
}

func (uapi *UAPIListener) Accept() (net.Conn, error) {
	return nil, nil
}

func (uapi *UAPIListener) Close() error {
	return uapi.listener.Close()
}

func (uapi *UAPIListener) Addr() net.Addr {
	return nil
}

func NewUAPIListener(name string) (net.Listener, error) {
	path := fmt.Sprintf(PipeNameFmt, name)
	return winio.ListenPipe(path, &winio.PipeConfig{
		InputBufferSize:  2048,
		OutputBufferSize: 2048,
	})
}
