/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"fmt"
	"strings"
)

// Config is a wireguard configuration.
type Config struct {
	Name       string
	PrivateKey PrivateKey
	Addresses  []CIDR
	ListenPort uint16
	MTU        uint16
	DNS        []IP
	Peers      []Peer
}

type Peer struct {
	PublicKey           Key
	PresharedKey        SymmetricKey
	AllowedIPs          []CIDR
	Endpoints           []Endpoint
	PersistentKeepalive uint16
}

type Endpoint struct {
	Host string
	Port uint16
}

func (e *Endpoint) String() string {
	if strings.IndexByte(e.Host, ':') > 0 {
		return fmt.Sprintf("[%s]:%d", e.Host, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Endpoint) IsEmpty() bool {
	return len(e.Host) == 0
}

// Copy makes a deep copy of Config.
// The result aliases no memory with the original.
func (cfg Config) Copy() Config {
	res := cfg
	if res.Addresses != nil {
		res.Addresses = append([]CIDR{}, res.Addresses...)
	}
	if res.DNS != nil {
		res.DNS = append([]IP{}, res.DNS...)
	}
	peers := make([]Peer, 0, len(res.Peers))
	for _, peer := range res.Peers {
		peers = append(peers, peer.Copy())
	}
	res.Peers = peers
	return res
}

// Copy makes a deep copy of Peer.
// The result aliases no memory with the original.
func (peer Peer) Copy() Peer {
	res := peer
	if res.AllowedIPs != nil {
		res.AllowedIPs = append([]CIDR{}, res.AllowedIPs...)
	}
	if res.Endpoints != nil {
		res.Endpoints = append([]Endpoint{}, res.Endpoints...)
	}
	return res
}
