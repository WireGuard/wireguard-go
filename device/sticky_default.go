//go:build !linux

package device

import (
	"github.com/amnezia-vpn/amnezia-wg/conn"
	"github.com/amnezia-vpn/amnezia-wg/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
