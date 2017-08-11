package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type IPCError struct {
	Code int64
}

func (s *IPCError) Error() string {
	return fmt.Sprintf("IPC error: %d", s.Code)
}

func (s *IPCError) ErrorCode() int64 {
	return s.Code
}

func ipcGetOperation(device *Device, socket *bufio.ReadWriter) *IPCError {

	// create lines

	device.mutex.RLock()
	device.net.mutex.RLock()

	lines := make([]string, 0, 100)
	send := func(line string) {
		lines = append(lines, line)
	}

	if !device.privateKey.IsZero() {
		send("private_key=" + device.privateKey.ToHex())
	}

	if device.net.addr != nil {
		send(fmt.Sprintf("listen_port=%d", device.net.addr.Port))
	}

	for _, peer := range device.peers {
		func() {
			peer.mutex.RLock()
			defer peer.mutex.RUnlock()
			send("public_key=" + peer.handshake.remoteStatic.ToHex())
			send("preshared_key=" + peer.handshake.presharedKey.ToHex())
			if peer.endpoint != nil {
				send("endpoint=" + peer.endpoint.String())
			}

			nano := atomic.LoadInt64(&peer.stats.lastHandshakeNano)
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			send(fmt.Sprintf("last_handshake_time_sec=%d", secs))
			send(fmt.Sprintf("last_handshake_time_nsec=%d", nano))
			send(fmt.Sprintf("tx_bytes=%d", peer.stats.txBytes))
			send(fmt.Sprintf("rx_bytes=%d", peer.stats.rxBytes))
			send(fmt.Sprintf("persistent_keepalive_interval=%d",
				atomic.LoadUint64(&peer.persistentKeepaliveInterval),
			))

			for _, ip := range device.routingTable.AllowedIPs(peer) {
				send("allowed_ip=" + ip.String())
			}
		}()
	}

	device.net.mutex.RUnlock()
	device.mutex.RUnlock()

	// send lines

	for _, line := range lines {
		_, err := socket.WriteString(line + "\n")
		if err != nil {
			return &IPCError{
				Code: ipcErrorIO,
			}
		}
	}

	return nil
}

func ipcSetOperation(device *Device, socket *bufio.ReadWriter) *IPCError {
	scanner := bufio.NewScanner(socket)
	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	var peer *Peer

	dummy := false
	deviceConfig := true

	for scanner.Scan() {

		// parse line

		line := scanner.Text()
		if line == "" {
			return nil
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			return &IPCError{Code: ipcErrorProtocol}
		}
		key := parts[0]
		value := parts[1]

		/* device configuration */

		if deviceConfig {

			switch key {
			case "private_key":
				var sk NoisePrivateKey
				if value == "" {
					device.SetPrivateKey(sk)
				} else {
					err := sk.FromHex(value)
					if err != nil {
						logError.Println("Failed to set private_key:", err)
						return &IPCError{Code: ipcErrorInvalid}
					}
					device.SetPrivateKey(sk)
				}

			case "listen_port":
				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					logError.Println("Failed to set listen_port:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
				if err != nil {
					logError.Println("Failed to set listen_port:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				netc := &device.net
				netc.mutex.Lock()
				netc.addr = addr
				netc.mutex.Unlock()
				err = updateUDPConn(device)
				if err != nil {
					logError.Println("Failed to set listen_port:", err)
					return &IPCError{Code: ipcErrorIO}
				}

				// TODO: Clear source address of all peers

			case "fwmark":
				logError.Println("FWMark not handled yet")
				// TODO: Clear source address of all peers

			case "public_key":

				// switch to peer configuration

				deviceConfig = false

			case "replace_peers":
				if value != "true" {
					logError.Println("Failed to set replace_peers, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}
				device.RemoveAllPeers()

			default:
				logError.Println("Invalid UAPI key (device configuration):", key)
				return &IPCError{Code: ipcErrorInvalid}
			}
		}

		/* peer configuration */

		if !deviceConfig {

			switch key {

			case "public_key":
				var pubKey NoisePublicKey
				err := pubKey.FromHex(value)
				if err != nil {
					logError.Println("Failed to get peer by public_key:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				// check if public key of peer equal to device

				device.mutex.RLock()
				if device.publicKey.Equals(pubKey) {

					// create dummy instance

					peer = &Peer{}
					dummy = true
					device.mutex.RUnlock()
					logInfo.Println("Ignoring peer with public key of device")

				} else {

					// find peer referenced

					peer, _ = device.peers[pubKey]
					device.mutex.RUnlock()
					if peer == nil {
						peer, err = device.NewPeer(pubKey)
						if err != nil {
							logError.Println("Failed to create new peer:", err)
							return &IPCError{Code: ipcErrorInvalid}
						}
					}
					signalSend(peer.signal.handshakeReset)
					dummy = false

				}

			case "remove":
				if value != "true" {
					logError.Println("Failed to set remove, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}
				if !dummy {
					logDebug.Println("Removing", peer.String())
					device.RemovePeer(peer.handshake.remoteStatic)
				}
				peer = &Peer{}
				dummy = true

			case "preshared_key":
				peer.mutex.Lock()
				err := peer.handshake.presharedKey.FromHex(value)
				peer.mutex.Unlock()
				if err != nil {
					logError.Println("Failed to set preshared_key:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

			case "endpoint":
				// TODO: Only IP and port
				addr, err := net.ResolveUDPAddr("udp", value)
				if err != nil {
					logError.Println("Failed to set endpoint:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}
				peer.mutex.Lock()
				peer.endpoint = addr
				peer.mutex.Unlock()
				signalSend(peer.signal.handshakeReset)

			case "persistent_keepalive_interval":

				// update keep-alive interval

				secs, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					logError.Println("Failed to set persistent_keepalive_interval:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				old := atomic.SwapUint64(
					&peer.persistentKeepaliveInterval,
					secs,
				)

				// send immediate keep-alive

				if old == 0 && secs != 0 {
					if err != nil {
						logError.Println("Failed to get tun device status:", err)
						return &IPCError{Code: ipcErrorIO}
					}
					if device.tun.isUp.Get() && !dummy {
						peer.SendKeepAlive()
					}
				}

			case "replace_allowed_ips":
				if value != "true" {
					logError.Println("Failed to set replace_allowed_ips, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}
				if !dummy {
					device.routingTable.RemovePeer(peer)
				}

			case "allowed_ip":
				_, network, err := net.ParseCIDR(value)
				if err != nil {
					logError.Println("Failed to set allowed_ip:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}
				ones, _ := network.Mask.Size()
				if !dummy {
					device.routingTable.Insert(network.IP, uint(ones), peer)
				}

			default:
				logError.Println("Invalid UAPI key (peer configuration):", key)
				return &IPCError{Code: ipcErrorInvalid}
			}
		}
	}

	return nil
}

func ipcHandle(device *Device, socket net.Conn) {

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
		device.log.Debug.Println("Config, set operation")
		status = ipcSetOperation(device, buffered)

	case "get=1\n":
		device.log.Debug.Println("Config, get operation")
		status = ipcGetOperation(device, buffered)

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
