package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

const (
	ipcErrorIO           = syscall.EIO
	ipcErrorNoPeer       = syscall.EPROTO
	ipcErrorNoKeyValue   = syscall.EPROTO
	ipcErrorInvalidKey   = syscall.EPROTO
	ipcErrorInvalidValue = syscall.EPROTO
)

type IPCError struct {
	Code syscall.Errno
}

func (s *IPCError) Error() string {
	return fmt.Sprintf("IPC error: %d", s.Code)
}

func (s *IPCError) ErrorCode() uintptr {
	return uintptr(s.Code)
}

func ipcGetOperation(device *Device, socket *bufio.ReadWriter) *IPCError {

	// create lines

	device.mutex.RLock()

	lines := make([]string, 0, 100)
	send := func(line string) {
		lines = append(lines, line)
	}

	if !device.privateKey.IsZero() {
		send("private_key=" + device.privateKey.ToHex())
	}

	send(fmt.Sprintf("listen_port=%d", device.net.addr.Port))

	for _, peer := range device.peers {
		func() {
			peer.mutex.RLock()
			defer peer.mutex.RUnlock()
			send("public_key=" + peer.handshake.remoteStatic.ToHex())
			send("preshared_key=" + peer.handshake.presharedKey.ToHex())
			if peer.endpoint != nil {
				send("endpoint=" + peer.endpoint.String())
			}
			send(fmt.Sprintf("tx_bytes=%d", peer.txBytes))
			send(fmt.Sprintf("rx_bytes=%d", peer.rxBytes))
			send(fmt.Sprintf("persistent_keepalive_interval=%d",
				atomic.LoadUint64(&peer.persistentKeepaliveInterval),
			))
			for _, ip := range device.routingTable.AllowedIPs(peer) {
				send("allowed_ip=" + ip.String())
			}
		}()
	}

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
	logError := device.log.Error
	logDebug := device.log.Debug

	var peer *Peer
	for scanner.Scan() {

		// parse line

		line := scanner.Text()
		if line == "" {
			return nil
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			return &IPCError{Code: ipcErrorNoKeyValue}
		}
		key := parts[0]
		value := parts[1]

		fmt.Println(key, value)

		switch key {

		/* interface configuration */

		case "private_key":
			var sk NoisePrivateKey
			if value == "" {
				device.SetPrivateKey(sk)
			} else {
				err := sk.FromHex(value)
				if err != nil {
					logError.Println("Failed to set private_key:", err)
					return &IPCError{Code: ipcErrorInvalidValue}
				}
				device.SetPrivateKey(sk)
			}

		case "listen_port":
			var port int
			_, err := fmt.Sscanf(value, "%d", &port)
			if err != nil || port > (1<<16) || port < 0 {
				logError.Println("Failed to set listen_port:", err)
				return &IPCError{Code: ipcErrorInvalidValue}
			}
			device.net.mutex.Lock()
			device.net.addr.Port = port
			device.net.conn, err = net.ListenUDP("udp", device.net.addr)
			device.net.mutex.Unlock()
			if err != nil {
				logError.Println("Failed to create UDP listener:", err)
				return &IPCError{Code: ipcErrorInvalidValue}
			}

		case "fwmark":
			logError.Println("FWMark not handled yet")

		case "public_key":
			var pubKey NoisePublicKey
			err := pubKey.FromHex(value)
			if err != nil {
				logError.Println("Failed to get peer by public_key:", err)
				return &IPCError{Code: ipcErrorInvalidValue}
			}
			device.mutex.RLock()
			found, ok := device.peers[pubKey]
			device.mutex.RUnlock()
			if ok {
				peer = found
			} else {
				peer = device.NewPeer(pubKey)
			}
			if peer == nil {
				panic(errors.New("bug: failed to find / create peer"))
			}

		case "replace_peers":
			if value == "true" {
				device.RemoveAllPeers()
			} else {
				logError.Println("Failed to set replace_peers, invalid value:", value)
				return &IPCError{Code: ipcErrorInvalidValue}
			}

		default:

			/* peer configuration */

			if peer == nil {
				logError.Println("No peer referenced, before peer operation")
				return &IPCError{Code: ipcErrorNoPeer}
			}

			switch key {

			case "remove":
				device.RemovePeer(peer.handshake.remoteStatic)
				logDebug.Println("Removing", peer.String())
				peer = nil

			case "preshared_key":
				err := func() error {
					peer.mutex.Lock()
					defer peer.mutex.Unlock()
					return peer.handshake.presharedKey.FromHex(value)
				}()
				if err != nil {
					logError.Println("Failed to set preshared_key:", err)
					return &IPCError{Code: ipcErrorInvalidValue}
				}

			case "endpoint":
				addr, err := net.ResolveUDPAddr("udp", value)
				if err != nil {
					logError.Println("Failed to set endpoint:", value)
					return &IPCError{Code: ipcErrorInvalidValue}
				}
				peer.mutex.Lock()
				peer.endpoint = addr
				peer.mutex.Unlock()

			case "persistent_keepalive_interval":
				secs, err := strconv.ParseInt(value, 10, 64)
				if secs < 0 || err != nil {
					logError.Println("Failed to set persistent_keepalive_interval:", err)
					return &IPCError{Code: ipcErrorInvalidValue}
				}
				atomic.StoreUint64(
					&peer.persistentKeepaliveInterval,
					uint64(secs),
				)

			case "replace_allowed_ips":
				if value == "true" {
					device.routingTable.RemovePeer(peer)
				} else {
					logError.Println("Failed to set replace_allowed_ips, invalid value:", value)
					return &IPCError{Code: ipcErrorInvalidValue}
				}

			case "allowed_ip":
				_, network, err := net.ParseCIDR(value)
				if err != nil {
					logError.Println("Failed to set allowed_ip:", err)
					return &IPCError{Code: ipcErrorInvalidValue}
				}
				ones, _ := network.Mask.Size()
				device.routingTable.Insert(network.IP, uint(ones), peer)

			default:
				logError.Println("Invalid UAPI key:", key)
				return &IPCError{Code: ipcErrorInvalidKey}
			}
		}
	}

	return nil
}

func ipcHandle(device *Device, socket net.Conn) {

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

	switch op {

	case "set=1\n":
		device.log.Debug.Println("Config, set operation")
		err := ipcSetOperation(device, buffered)
		if err != nil {
			fmt.Fprintf(buffered, "errno=%d\n\n", err.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		return

	case "get=1\n":
		device.log.Debug.Println("Config, get operation")
		err := ipcGetOperation(device, buffered)
		if err != nil {
			fmt.Fprintf(buffered, "errno=%d\n\n", err.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		return

	default:
		device.log.Error.Println("Invalid UAPI operation:", op)

	}
}
