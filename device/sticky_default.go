//go:build !linux

package device

import (
	"github.com/rohrerj/scion-over-wireguard/conn"
	"github.com/rohrerj/scion-over-wireguard/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
