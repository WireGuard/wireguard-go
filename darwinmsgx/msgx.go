//go:build darwin

// This shit is cursed but fuck it we ball

package darwinmsgx

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type MsghdrX struct {
	unix.Msghdr
	DataLen uintptr
}

func SendmsgX(conn syscall.RawConn, msghdrs []MsghdrX) (int, error) {
	var operr error
	totalSent := 0
	err := conn.Write(func(fd uintptr) bool {
		for len(msghdrs)-totalSent > 0 {
			sent, _, err := unix.Syscall6(
				unix.SYS_SENDMSG_X,
				fd,
				uintptr(unsafe.Pointer(&msghdrs[totalSent])),
				uintptr(len(msghdrs)-totalSent), // number of messages
				0,                               // flags
				0,                               // _
				0,                               // _
			)
			totalSent += int(sent)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return false
			}
			if err != 0 {
				operr = os.NewSyscallError("sendmsg_x", err)
				return true
			}
		}
		return true
	})
	if operr != nil {
		return totalSent, operr
	}
	if err != nil {
		return totalSent, err
	}
	return totalSent, nil
}

func RecvmsgX(conn syscall.RawConn, msghdrs []MsghdrX) (int, error) {
	var opErr error
	received := 0
	err := conn.Read(func(fd uintptr) bool {
		rec, _, err := unix.Syscall6(
			unix.SYS_RECVMSG_X,
			fd,
			uintptr(unsafe.Pointer(&msghdrs[0])),
			uintptr(len(msghdrs)), // number of messages
			0,                     // flags
			0,                     // _
			0,                     // _
		)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return false
		}
		if err != 0 {
			opErr = os.NewSyscallError("recvmsg_x", err)
			return true
		}
		received = int(rec)
		return true
	})
	if opErr != nil {
		return received, opErr
	}
	if err != nil {
		return received, err
	}
	return received, opErr
}
