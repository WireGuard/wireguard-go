/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgcfg

import (
	"reflect"
	"runtime"
	"testing"
)

const testInput = `
[Interface] 
Address = 10.192.122.1/24 
Address = 10.10.0.1/16 
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk= 
ListenPort = 51820  #comments don't matter

[Peer] 
PublicKey   =   xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=    
Endpoint = 192.95.5.67:1234 
AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

[Peer] 
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0= 
Endpoint = [2607:5300:60:6b0::c05f:543]:2468 
AllowedIPs = 10.192.122.4/32, 192.168.0.0/16
PersistentKeepalive = 100

[Peer] 
PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA= 
PresharedKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0= 
Endpoint = test.wireguard.com:18981 
AllowedIPs = 10.10.10.230/32`

func noError(t *testing.T, err error) bool {
	if err == nil {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error at %s:%d: %#v", fn, line, err)
	return false
}

func equal(t *testing.T, expected, actual interface{}) bool {
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Failed equals at %s:%d\nactual   %#v\nexpected %#v", fn, line, actual, expected)
	return false
}
func lenTest(t *testing.T, actualO interface{}, expected int) bool {
	actual := reflect.ValueOf(actualO).Len()
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Wrong length at %s:%d\nactual   %#v\nexpected %#v", fn, line, actual, expected)
	return false
}
func contains(t *testing.T, list, element interface{}) bool {
	listValue := reflect.ValueOf(list)
	for i := 0; i < listValue.Len(); i++ {
		if reflect.DeepEqual(listValue.Index(i).Interface(), element) {
			return true
		}
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error %s:%d\nelement not found: %#v", fn, line, element)
	return false
}

func TestFromWgQuick(t *testing.T) {
	conf, err := FromWgQuick(testInput, "test")
	if noError(t, err) {

		lenTest(t, conf.Addresses, 2)
		contains(t, conf.Addresses, CIDR{IPv4(10, 10, 0, 1), 16})
		contains(t, conf.Addresses, CIDR{IPv4(10, 192, 122, 1), 24})
		equal(t, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", conf.PrivateKey.String())
		equal(t, uint16(51820), conf.ListenPort)

		lenTest(t, conf.Peers, 3)
		lenTest(t, conf.Peers[0].AllowedIPs, 2)
		equal(t, Endpoint{Host: "192.95.5.67", Port: 1234}, conf.Peers[0].Endpoints[0])
		equal(t, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", conf.Peers[0].PublicKey.Base64())

		lenTest(t, conf.Peers[1].AllowedIPs, 2)
		equal(t, Endpoint{Host: "2607:5300:60:6b0::c05f:543", Port: 2468}, conf.Peers[1].Endpoints[0])
		equal(t, "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", conf.Peers[1].PublicKey.Base64())
		equal(t, uint16(100), conf.Peers[1].PersistentKeepalive)

		lenTest(t, conf.Peers[2].AllowedIPs, 1)
		equal(t, Endpoint{Host: "test.wireguard.com", Port: 18981}, conf.Peers[2].Endpoints[0])
		equal(t, "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=", conf.Peers[2].PublicKey.Base64())
		equal(t, "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", conf.Peers[2].PresharedKey.Base64())
	}
}

func TestParseEndpoint(t *testing.T) {
	_, err := parseEndpoint("[192.168.42.0:]:51880")
	if err == nil {
		t.Error("Error was expected")
	}
	e, err := parseEndpoint("192.168.42.0:51880")
	if noError(t, err) {
		equal(t, "192.168.42.0", e.Host)
		equal(t, uint16(51880), e.Port)
	}
	e, err = parseEndpoint("test.wireguard.com:18981")
	if noError(t, err) {
		equal(t, "test.wireguard.com", e.Host)
		equal(t, uint16(18981), e.Port)
	}
	e, err = parseEndpoint("[2607:5300:60:6b0::c05f:543]:2468")
	if noError(t, err) {
		equal(t, "2607:5300:60:6b0::c05f:543", e.Host)
		equal(t, uint16(2468), e.Port)
	}
	_, err = parseEndpoint("[::::::invalid:18981")
	if err == nil {
		t.Error("Error was expected")
	}
}
