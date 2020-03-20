/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgcfg

import (
	"fmt"
	"net"
	"strings"
)

func (conf *Config) ToUAPI() (string, error) {
	output := new(strings.Builder)
	fmt.Fprintf(output, "private_key=%s\n", conf.PrivateKey.HexString())

	if conf.ListenPort > 0 {
		fmt.Fprintf(output, "listen_port=%d\n", conf.ListenPort)
	}

	output.WriteString("replace_peers=true\n")

	for _, peer := range conf.Peers {
		fmt.Fprintf(output, "public_key=%s\n", peer.PublicKey.HexString())
		fmt.Fprintf(output, "protocol_version=1\n")
		fmt.Fprintf(output, "replace_allowed_ips=true\n")

		if !peer.PresharedKey.IsZero() {
			fmt.Fprintf(output, "preshared_key = %s\n", peer.PresharedKey.String())
		}

		if len(peer.AllowedIPs) > 0 {
			for _, address := range peer.AllowedIPs {
				fmt.Fprintf(output, "allowed_ip=%s\n", address.String())
			}
		}

		if len(peer.Endpoints) > 0 {
			var reps []string
			for _, ep := range peer.Endpoints {
				ips, err := net.LookupIP(ep.Host)
				if err != nil {
					return "", err
				}
				var ip net.IP
				for _, iterip := range ips {
					if ip4 := iterip.To4(); ip4 != nil {
						ip = ip4
						break
					}
					if ip == nil {
						ip = iterip
					}
				}
				if ip == nil {
					return "", fmt.Errorf("unable to resolve IP address of endpoint %q (%v)", ep.Host, ips)
				}
				resolvedEndpoint := Endpoint{ip.String(), ep.Port}
				reps = append(reps, resolvedEndpoint.String())
			}
			fmt.Fprintf(output, "endpoint=%s\n", strings.Join(reps, ","))
		} else {
			fmt.Fprint(output, "endpoint=\n")
		}

		// Note: this needs to come *after* endpoint definitions,
		// because setting it will trigger a handshake to all
		// already-defined endpoints.
		fmt.Fprintf(output, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}
	return output.String(), nil
}
