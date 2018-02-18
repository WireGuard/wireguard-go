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

	device.log.Debug.Println("UAPI: Processing get operation")

	// create lines

	lines := make([]string, 0, 100)
	send := func(line string) {
		lines = append(lines, line)
	}

	func() {

		// lock required resources

		device.net.mutex.RLock()
		defer device.net.mutex.RUnlock()

		device.noise.mutex.RLock()
		defer device.noise.mutex.RUnlock()

		device.routing.mutex.RLock()
		defer device.routing.mutex.RUnlock()

		device.peers.mutex.Lock()
		defer device.peers.mutex.Unlock()

		// serialize device related values

		if !device.noise.privateKey.IsZero() {
			send("private_key=" + device.noise.privateKey.ToHex())
		}

		if device.net.port != 0 {
			send(fmt.Sprintf("listen_port=%d", device.net.port))
		}

		if device.net.fwmark != 0 {
			send(fmt.Sprintf("fwmark=%d", device.net.fwmark))
		}

		// serialize each peer state

		for _, peer := range device.peers.keyMap {
			peer.mutex.RLock()
			defer peer.mutex.RUnlock()

			send("public_key=" + peer.handshake.remoteStatic.ToHex())
			send("preshared_key=" + peer.handshake.presharedKey.ToHex())
			if peer.endpoint != nil {
				send("endpoint=" + peer.endpoint.DstToString())
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

			for _, ip := range device.routing.table.AllowedIPs(peer) {
				send("allowed_ip=" + ip.String())
			}

		}
	}()

	// send lines (does not require resource locks)

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
				err := sk.FromHex(value)
				if err != nil {
					logError.Println("Failed to set private_key:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}
				logDebug.Println("UAPI: Updating device private key")
				device.SetPrivateKey(sk)

			case "listen_port":

				// parse port number

				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					logError.Println("Failed to parse listen_port:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				// update port and rebind

				logDebug.Println("UAPI: Updating listen port")

				device.net.mutex.Lock()
				device.net.port = uint16(port)
				device.net.mutex.Unlock()

				if err := device.BindUpdate(); err != nil {
					logError.Println("Failed to set listen_port:", err)
					return &IPCError{Code: ipcErrorPortInUse}
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
					return &IPCError{Code: ipcErrorInvalid}
				}

				logDebug.Println("UAPI: Updating fwmark")

				if err := device.BindSetMark(uint32(fwmark)); err != nil {
					logError.Println("Failed to update fwmark:", err)
					return &IPCError{Code: ipcErrorPortInUse}
				}

			case "public_key":
				// switch to peer configuration
				logDebug.Println("UAPI: Transition to peer configuration")
				deviceConfig = false

			case "replace_peers":
				if value != "true" {
					logError.Println("Failed to set replace_peers, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}
				logDebug.Println("UAPI: Removing all peers")
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
				var publicKey NoisePublicKey
				err := publicKey.FromHex(value)
				if err != nil {
					logError.Println("Failed to get peer by public_key:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				// ignore peer with public key of device

				device.noise.mutex.RLock()
				equals := device.noise.publicKey.Equals(publicKey)
				device.noise.mutex.RUnlock()

				if equals {
					peer = &Peer{}
					dummy = true
				}

				// find peer referenced

				peer = device.LookupPeer(publicKey)

				if peer == nil {
					peer, err = device.NewPeer(publicKey)
					if err != nil {
						logError.Println("Failed to create new peer:", err)
						return &IPCError{Code: ipcErrorInvalid}
					}
					logDebug.Println("UAPI: Created new peer:", peer.String())
				}

				peer.mutex.Lock()
				peer.timer.handshakeDeadline.Reset(RekeyAttemptTime)
				peer.mutex.Unlock()

			case "remove":

				// remove currently selected peer from device

				if value != "true" {
					logError.Println("Failed to set remove, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}
				if !dummy {
					logDebug.Println("UAPI: Removing peer:", peer.String())
					device.RemovePeer(peer.handshake.remoteStatic)
				}
				peer = &Peer{}
				dummy = true

			case "preshared_key":

				// update PSK

				logDebug.Println("UAPI: Updating pre-shared key for peer:", peer.String())

				peer.handshake.mutex.Lock()
				err := peer.handshake.presharedKey.FromHex(value)
				peer.handshake.mutex.Unlock()

				if err != nil {
					logError.Println("Failed to set preshared_key:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

			case "endpoint":

				// set endpoint destination

				logDebug.Println("UAPI: Updating endpoint for peer:", peer.String())

				err := func() error {
					peer.mutex.Lock()
					defer peer.mutex.Unlock()
					endpoint, err := CreateEndpoint(value)
					if err != nil {
						return err
					}
					peer.endpoint = endpoint
					peer.timer.handshakeDeadline.Reset(RekeyAttemptTime)
					return nil
				}()

				if err != nil {
					logError.Println("Failed to set endpoint:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}

			case "persistent_keepalive_interval":

				// update keep-alive interval

				logDebug.Println("UAPI: Updating persistent_keepalive_interval for peer:", peer.String())

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
					if device.isUp.Get() && !dummy {
						peer.SendKeepAlive()
					}
				}

			case "replace_allowed_ips":

				logDebug.Println("UAPI: Removing all allowed IPs for peer:", peer.String())

				if value != "true" {
					logError.Println("Failed to set replace_allowed_ips, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalid}
				}

				if dummy {
					continue
				}

				device.routing.mutex.Lock()
				device.routing.table.RemovePeer(peer)
				device.routing.mutex.Unlock()

			case "allowed_ip":

				logDebug.Println("UAPI: Adding allowed_ip to peer:", peer.String())

				_, network, err := net.ParseCIDR(value)
				if err != nil {
					logError.Println("Failed to set allowed_ip:", err)
					return &IPCError{Code: ipcErrorInvalid}
				}

				if dummy {
					continue
				}

				ones, _ := network.Mask.Size()
				device.routing.mutex.Lock()
				device.routing.table.Insert(network.IP, uint(ones), peer)
				device.routing.mutex.Unlock()

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
