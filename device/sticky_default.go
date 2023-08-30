//go:build !linux

package device

import (
	"github.com/zeronetworks/zn-wireguard-go/conn"
	"github.com/zeronetworks/zn-wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
