package conn

import (
	"golang.org/x/sys/windows"
)

func (bind *WinRingBind) OpenOnLocalhost(port uint16) ([]ReceiveFunc, uint16, error) {
	return bind.OpenOnAddr([4]byte{127, 0, 0, 1}, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, port)
}

func (bind *WinRingBind) OpenOnAddr(ipv4addr [4]byte, ipv6addr [16]byte, port uint16) (recvFns []ReceiveFunc, selectedPort uint16, err error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	defer func() {
		if err != nil {
			bind.closeAndZero()
		}
	}()
	if bind.isOpen.Load() != 0 {
		return nil, 0, ErrBindAlreadyOpen
	}
	var sa windows.Sockaddr
	sa, err = bind.v4.Open(windows.AF_INET, &windows.SockaddrInet4{Addr: ipv4addr, Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	sa, err = bind.v6.Open(windows.AF_INET6, &windows.SockaddrInet6{Addr: ipv6addr, Port: sa.(*windows.SockaddrInet4).Port})
	if err != nil {
		return nil, 0, err
	}
	selectedPort = uint16(sa.(*windows.SockaddrInet6).Port)
	for i := 0; i < packetsPerRing; i++ {
		err = bind.v4.InsertReceiveRequest()
		if err != nil {
			return nil, 0, err
		}
		err = bind.v6.InsertReceiveRequest()
		if err != nil {
			return nil, 0, err
		}
	}
	bind.isOpen.Store(1)
	return []ReceiveFunc{bind.receiveIPv4, bind.receiveIPv6}, selectedPort, err
}
