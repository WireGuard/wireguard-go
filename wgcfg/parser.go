/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgcfg

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: ‘%s’", e.why, e.offender)
}

func parseEndpoints(s string) ([]Endpoint, error) {
	var eps []Endpoint
	vals := strings.Split(s, ",")
	for _, val := range vals {
		e, err := parseEndpoint(val)
		if err != nil {
			return nil, err
		}
		eps = append(eps, *e)
	}
	return eps, nil
}

func parseEndpoint(s string) (*Endpoint, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, &ParseError{"Missing port from endpoint", s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return nil, &ParseError{"Invalid endpoint host", host}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{"Brackets must contain an IPv6 address", host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			maybeV6 := net.ParseIP(host[1 : len(host)-1])
			if maybeV6 == nil || len(maybeV6) != net.IPv6len {
				return nil, err
			}
		} else {
			return nil, err
		}
		host = host[1 : len(host)-1]
	}
	return &Endpoint{host, uint16(port)}, nil
}

func parseMTU(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 576 || m > 65535 {
		return 0, &ParseError{"Invalid MTU", s}
	}
	return uint16(m), nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid port", s}
	}
	return uint16(m), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid persistent keepalive", s}
	}
	return uint16(m), nil
}

func parseKeyHex(s string) (*Key, error) {
	k, err := hex.DecodeString(s)
	if err != nil {
		return nil, &ParseError{"Invalid key: " + err.Error(), s}
	}
	if len(k) != KeySize {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func parseBytesOrStamp(s string) (uint64, error) {
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{"Number must be a number between 0 and 2^64-1: " + err.Error(), s}
	}
	return b, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for _, split := range strings.Split(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{"Two commas in a row", s}
		}
		out = append(out, trim)
	}
	return out, nil
}

type parserState int

const (
	inInterfaceSection parserState = iota
	inPeerSection
	notInASection
)

func (c *Config) maybeAddPeer(p *Peer) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

func FromWgQuick(s string, name string) (*Config, error) {
	if !TunnelNameIsValid(name) {
		return nil, &ParseError{"Tunnel name is not valid", name}
	}
	lines := strings.Split(s, "\n")
	parserState := notInASection
	conf := Config{Name: name}
	sawPrivateKey := false
	var peer *Peer
	for _, line := range lines {
		pound := strings.IndexByte(line, '#')
		if pound >= 0 {
			line = line[:pound]
		}
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if len(line) == 0 {
			continue
		}
		if lineLower == "[interface]" {
			conf.maybeAddPeer(peer)
			parserState = inInterfaceSection
			continue
		}
		if lineLower == "[peer]" {
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
			continue
		}
		if parserState == notInASection {
			return nil, &ParseError{"Line must occur in a section", line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{"Invalid config key is missing an equals separator", line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return nil, &ParseError{"Key must have a value", line}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "privatekey":
				k, err := ParseKey(val)
				if err != nil {
					return nil, err
				}
				conf.PrivateKey = PrivateKey(*k)
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.ListenPort = p
			case "mtu":
				m, err := parseMTU(val)
				if err != nil {
					return nil, err
				}
				conf.MTU = m
			case "address":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := ParseCIDR(address)
					if err != nil {
						return nil, err
					}
					conf.Addresses = append(conf.Addresses, a)
				}
			case "dns":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, ok := ParseIP(address)
					if !ok {
						return nil, &ParseError{"Invalid IP address", address}
					}
					conf.DNS = append(conf.DNS, a)
				}
			default:
				return nil, &ParseError{"Invalid key for [Interface] section", key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "publickey":
				k, err := ParseKey(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := ParseKey(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = SymmetricKey(*k)
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := ParseCIDR(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				eps, err := parseEndpoints(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoints = eps
			default:
				return nil, &ParseError{"Invalid key for [Peer] section", key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	if !sawPrivateKey {
		return nil, &ParseError{"An interface must have a private key", "[none specified]"}
	}
	for _, p := range conf.Peers {
		if p.PublicKey.IsZero() {
			return nil, &ParseError{"All peers must have public keys", "[none specified]"}
		}
	}

	return &conf, nil
}

// TODO(apenwarr): This is incompatibe with current Device.IpcSetOperation.
//  It duplicates all the parser stuff in there, but is missing some
//  keywords. Nothing useful seems to need it anymore.
func Broken_FromUAPI(s string, existingConfig *Config) (*Config, error) {
	lines := strings.Split(s, "\n")
	parserState := inInterfaceSection
	conf := Config{
		Name:      existingConfig.Name,
		Addresses: existingConfig.Addresses,
		DNS:       existingConfig.DNS,
		MTU:       existingConfig.MTU,
	}
	var peer *Peer
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{"Invalid config key is missing an equals separator", line}
		}
		key, val := line[:equals], line[equals+1:]
		if len(val) == 0 {
			return nil, &ParseError{"Key must have a value", line}
		}
		switch key {
		case "public_key":
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
		case "errno":
			if val == "0" {
				continue
			} else {
				return nil, &ParseError{"Error in getting configuration", val}
			}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "private_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				conf.PrivateKey = PrivateKey(*k)
			case "listen_port":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.ListenPort = p
			case "fwmark":
				// Ignored for now.

			default:
				return nil, &ParseError{"Invalid key for interface section", key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "public_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "preshared_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = SymmetricKey(*k)
			case "protocol_version":
				if val != "1" {
					return nil, &ParseError{"Protocol version must be 1", val}
				}
			case "allowed_ip":
				a, err := ParseCIDR(val)
				if err != nil {
					return nil, err
				}
				peer.AllowedIPs = append(peer.AllowedIPs, a)
			case "persistent_keepalive_interval":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				eps, err := parseEndpoints(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoints = eps
			default:
				return nil, &ParseError{"Invalid key for peer section", key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	return &conf, nil
}
