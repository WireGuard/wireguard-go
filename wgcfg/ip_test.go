/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgcfg_test

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgcfg"
)

func TestCIDRContains(t *testing.T) {
	t.Run("home router test", func(t *testing.T) {
		r, err := wgcfg.ParseCIDR("192.168.0.0/24")
		if err != nil {
			t.Fatal(err)
		}
		ip := wgcfg.ParseIP("192.168.0.1")
		if ip == nil {
			t.Fatalf("address failed to parse")
		}
		if !r.Contains(ip) {
			t.Fatalf("'%s' should contain '%s'", r, ip)
		}
	})

	t.Run("IPv4 outside network", func(t *testing.T) {
		r, err := wgcfg.ParseCIDR("192.168.0.0/30")
		if err != nil {
			t.Fatal(err)
		}
		ip := wgcfg.ParseIP("192.168.0.4")
		if ip == nil {
			t.Fatalf("address failed to parse")
		}
		if r.Contains(ip) {
			t.Fatalf("'%s' should not contain '%s'", r, ip)
		}
	})

	t.Run("IPv4 does not contain IPv6", func(t *testing.T) {
		r, err := wgcfg.ParseCIDR("192.168.0.0/24")
		if err != nil {
			t.Fatal(err)
		}
		ip := wgcfg.ParseIP("2001:db8:85a3:0:0:8a2e:370:7334")
		if ip == nil {
			t.Fatalf("address failed to parse")
		}
		if r.Contains(ip) {
			t.Fatalf("'%s' should not contain '%s'", r, ip)
		}
	})

	t.Run("IPv6 inside network", func(t *testing.T) {
		r, err := wgcfg.ParseCIDR("2001:db8:1234::/48")
		if err != nil {
			t.Fatal(err)
		}
		ip := wgcfg.ParseIP("2001:db8:1234:0000:0000:0000:0000:0001")
		if ip == nil {
			t.Fatalf("ParseIP returned nil pointer")
		}
		if !r.Contains(ip) {
			t.Fatalf("'%s' should not contain '%s'", r, ip)
		}
	})

	t.Run("IPv6 outside network", func(t *testing.T) {
		r, err := wgcfg.ParseCIDR("2001:db8:1234:0:190b:0:1982::/126")
		if err != nil {
			t.Fatal(err)
		}
		ip := wgcfg.ParseIP("2001:db8:1234:0:190b:0:1982:4")
		if ip == nil {
			t.Fatalf("ParseIP returned nil pointer")
		}
		if r.Contains(ip) {
			t.Fatalf("'%s' should not contain '%s'", r, ip)
		}
	})
}

func BenchmarkCIDRContainsIPv4(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		r, err := wgcfg.ParseCIDR("192.168.1.0/24")
		if err != nil {
			b.Fatal(err)
		}
		ip := wgcfg.ParseIP("1.2.3.4")
		if ip == nil {
			b.Fatalf("ParseIP returned nil pointer")
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r.Contains(ip)
		}
	})

	b.Run("IPv6", func(b *testing.B) {
		r, err := wgcfg.ParseCIDR("2001:db8:1234::/48")
		if err != nil {
			b.Fatal(err)
		}
		ip := wgcfg.ParseIP("2001:db8:1234:0000:0000:0000:0000:0001")
		if ip == nil {
			b.Fatalf("ParseIP returned nil pointer")
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r.Contains(ip)
		}
	})
}
