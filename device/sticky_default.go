//go:build !linux

package device

import (
	"github.com/NordSecurity/wireguard-go/conn"
	"github.com/NordSecurity/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
