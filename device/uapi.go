/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/ipc"
)

type IPCError struct {
	int64
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error: %d", s.int64)
}

func (s IPCError) ErrorCode() int64 {
	return s.int64
}

func (device *Device) IpcGetOperation(socket *bufio.Writer) error {
	lines := make([]string, 0, 100)
	send := func(line string) {
		lines = append(lines, line)
	}

	func() {

		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			send("private_key=" + device.staticIdentity.privateKey.ToHex())
		}

		if device.net.port != 0 {
			send(fmt.Sprintf("listen_port=%d", device.net.port))
		}

		if device.net.fwmark != 0 {
			send(fmt.Sprintf("fwmark=%d", device.net.fwmark))
		}

		// serialize each peer state

		for _, peer := range device.peers.keyMap {
			peer.RLock()
			defer peer.RUnlock()

			send("public_key=" + peer.handshake.remoteStatic.ToHex())
			send("preshared_key=" + peer.handshake.presharedKey.ToHex())
			send("protocol_version=1")
			if peer.endpoint != nil {
				send("endpoint=" + peer.endpoint.DstToString())
			}

			nano := atomic.LoadInt64(&peer.stats.lastHandshakeNano)
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			send(fmt.Sprintf("last_handshake_time_sec=%d", secs))
			send(fmt.Sprintf("last_handshake_time_nsec=%d", nano))
			send(fmt.Sprintf("tx_bytes=%d", atomic.LoadUint64(&peer.stats.txBytes)))
			send(fmt.Sprintf("rx_bytes=%d", atomic.LoadUint64(&peer.stats.rxBytes)))
			send(fmt.Sprintf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval))

			for _, ip := range device.allowedips.EntriesForPeer(peer) {
				send("allowed_ip=" + ip.String())
			}

		}
	}()

	// send lines (does not require resource locks)

	for _, line := range lines {
		_, err := socket.WriteString(line + "\n")
		if err != nil {
			return &IPCError{ipc.IpcErrorIO}
		}
	}

	return nil
}

func (device *Device) IpcSetOperation(socket *bufio.Reader) error {
	scanner := bufio.NewScanner(socket)
	logError := device.log.Error
	logDebug := device.log.Debug

	var peer *Peer

	dummy := false
	createdNewPeer := false
	deviceConfig := true

	for scanner.Scan() {

		// parse line

		line := scanner.Text()
		if line == "" {
			return nil
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			return &IPCError{ipc.IpcErrorProtocol}
		}
		key := parts[0]
		value := parts[1]

		/* device configuration */

		if deviceConfig {

			switch key {
			case "private_key":
				var sk NoisePrivateKey
				err := sk.FromMaybeZeroHex(value)
				if err != nil {
					logError.Println("Failed to set private_key:", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}
				logDebug.Println("UAPI: Updating private key")
				device.SetPrivateKey(sk)

			case "listen_port":

				// parse port number

				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					logError.Println("Failed to parse listen_port:", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}

				// update port and rebind

				logDebug.Println("UAPI: Updating listen port")

				device.net.Lock()
				device.net.port = uint16(port)
				device.net.Unlock()

				if err := device.BindUpdate(); err != nil {
					logError.Println("Failed to set listen_port:", err)
					return &IPCError{ipc.IpcErrorPortInUse}
				}

			case "fwmark":

				// parse fwmark field

				fwmark, err := func() (uint32, error) {
					if value == "" {
						return 0, nil
					}
					mark, err := strconv.ParseUint(value, 10, 32)
					return uint32(mark), err
				}()

				if err != nil {
					logError.Println("Invalid fwmark", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}

				logDebug.Println("UAPI: Updating fwmark")

				if err := device.BindSetMark(uint32(fwmark)); err != nil {
					logError.Println("Failed to update fwmark:", err)
					return &IPCError{ipc.IpcErrorPortInUse}
				}

			case "public_key":
				// switch to peer configuration
				logDebug.Println("UAPI: Transition to peer configuration")
				deviceConfig = false

			case "replace_peers":
				if value != "true" {
					logError.Println("Failed to set replace_peers, invalid value:", value)
					return &IPCError{ipc.IpcErrorInvalid}
				}
				logDebug.Println("UAPI: Removing all peers")
				device.RemoveAllPeers()

			default:
				logError.Println("Invalid UAPI device key:", key)
				return &IPCError{ipc.IpcErrorInvalid}
			}
		}

		/* peer configuration */

		if !deviceConfig {

			switch key {

			case "public_key":
				var publicKey NoisePublicKey
				err := publicKey.FromHex(value)
				if err != nil {
					logError.Println("Failed to get peer by public key:", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}

				// ignore peer with public key of device

				device.staticIdentity.RLock()
				dummy = device.staticIdentity.publicKey.Equals(publicKey)
				device.staticIdentity.RUnlock()

				if dummy {
					peer = &Peer{}
				} else {
					peer = device.LookupPeer(publicKey)
				}

				createdNewPeer = peer == nil
				if createdNewPeer {
					peer, err = device.NewPeer(publicKey)
					if err != nil {
						logError.Println("Failed to create new peer:", err)
						return &IPCError{ipc.IpcErrorInvalid}
					}
					if peer == nil {
						dummy = true
						peer = &Peer{}
					} else {
						logDebug.Println(peer, "- UAPI: Created")
					}
				}

			case "update_only":

				// allow disabling of creation

				if value != "true" {
					logError.Println("Failed to set update only, invalid value:", value)
					return &IPCError{ipc.IpcErrorInvalid}
				}
				if createdNewPeer && !dummy {
					device.RemovePeer(peer.handshake.remoteStatic)
					peer = &Peer{}
					dummy = true
				}

			case "remove":

				// remove currently selected peer from device

				if value != "true" {
					logError.Println("Failed to set remove, invalid value:", value)
					return &IPCError{ipc.IpcErrorInvalid}
				}
				if !dummy {
					logDebug.Println(peer, "- UAPI: Removing")
					device.RemovePeer(peer.handshake.remoteStatic)
				}
				peer = &Peer{}
				dummy = true

			case "preshared_key":

				// update PSK

				logDebug.Println(peer, "- UAPI: Updating preshared key")

				peer.handshake.mutex.Lock()
				err := peer.handshake.presharedKey.FromHex(value)
				peer.handshake.mutex.Unlock()

				if err != nil {
					logError.Println("Failed to set preshared key:", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}

			case "endpoint":

				// set endpoint destination

				logDebug.Println(peer, "- UAPI: Updating endpoint")

				err := func() error {
					peer.Lock()
					defer peer.Unlock()
					endpoint, err := conn.CreateEndpoint(value)
					if err != nil {
						return err
					}
					peer.endpoint = endpoint
					return nil
				}()

				if err != nil {
					logError.Println("Failed to set endpoint:", err, ":", value)
					return &IPCError{ipc.IpcErrorInvalid}
				}

			case "persistent_keepalive_interval":

				// update persistent keepalive interval

				logDebug.Println(peer, "- UAPI: Updating persistent keepalive interval")

				secs, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					logError.Println("Failed to set persistent keepalive interval:", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}

				old := peer.persistentKeepaliveInterval
				peer.persistentKeepaliveInterval = uint16(secs)

				// send immediate keepalive if we're turning it on and before it wasn't on

				if old == 0 && secs != 0 {
					if err != nil {
						logError.Println("Failed to get tun device status:", err)
						return &IPCError{ipc.IpcErrorIO}
					}
					if device.isUp.Get() && !dummy {
						peer.SendKeepalive()
					}
				}

			case "replace_allowed_ips":

				logDebug.Println(peer, "- UAPI: Removing all allowedips")

				if value != "true" {
					logError.Println("Failed to replace allowedips, invalid value:", value)
					return &IPCError{ipc.IpcErrorInvalid}
				}

				if dummy {
					continue
				}

				device.allowedips.RemoveByPeer(peer)

			case "allowed_ip":

				logDebug.Println(peer, "- UAPI: Adding allowedip")

				_, network, err := net.ParseCIDR(value)
				if err != nil {
					logError.Println("Failed to set allowed ip:", err)
					return &IPCError{ipc.IpcErrorInvalid}
				}

				if dummy {
					continue
				}

				ones, _ := network.Mask.Size()
				device.allowedips.Insert(network.IP, uint(ones), peer)

			case "protocol_version":

				if value != "1" {
					logError.Println("Invalid protocol version:", value)
					return &IPCError{ipc.IpcErrorInvalid}
				}

			default:
				logError.Println("Invalid UAPI peer key:", key)
				return &IPCError{ipc.IpcErrorInvalid}
			}
		}
	}

	return nil
}

func (device *Device) IpcHandle(socket net.Conn) {

	// create buffered read/writer

	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	defer buffered.Flush()

	op, err := buffered.ReadString('\n')
	if err != nil {
		return
	}

	// handle operation

	var status *IPCError

	switch op {
	case "set=1\n":
		err = device.IpcSetOperation(buffered.Reader)
		if !errors.As(err, &status) {
			// should never happen
			device.log.Error.Println("Invalid UAPI error:", err)
			status = &IPCError{1}
		}

	case "get=1\n":
		err = device.IpcGetOperation(buffered.Writer)
		if !errors.As(err, &status) {
			// should never happen
			device.log.Error.Println("Invalid UAPI error:", err)
			status = &IPCError{1}
		}

	default:
		device.log.Error.Println("Invalid UAPI operation:", op)
		return
	}

	// write status

	if status != nil {
		device.log.Error.Println(status)
		fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
	} else {
		fmt.Fprintf(buffered, "errno=0\n\n")
	}
}
