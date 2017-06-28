package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

/* TODO : use real error code
 * Many of which will be the same
 */
const (
	ipcErrorNoPeer            = 0
	ipcErrorNoKeyValue        = 1
	ipcErrorInvalidKey        = 2
	ipcErrorInvalidValue      = 2
	ipcErrorInvalidPrivateKey = 3
	ipcErrorInvalidPublicKey  = 4
	ipcErrorInvalidPort       = 5
	ipcErrorInvalidIPAddress  = 6
)

type IPCError struct {
	Code int
}

func (s *IPCError) Error() string {
	return fmt.Sprintf("IPC error: %d", s.Code)
}

func (s *IPCError) ErrorCode() int {
	return s.Code
}

func ipcGetOperation(device *Device, socket *bufio.ReadWriter) error {

	device.mutex.RLock()
	defer device.mutex.RUnlock()

	// create lines

	lines := make([]string, 0, 100)
	send := func(line string) {
		lines = append(lines, line)
	}

	if !device.privateKey.IsZero() {
		send("private_key=" + device.privateKey.ToHex())
	}

	if device.address != nil {
		send(fmt.Sprintf("listen_port=%d", device.address.Port))
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
			send(fmt.Sprintf("tx_bytes=%d", peer.tx_bytes))
			send(fmt.Sprintf("rx_bytes=%d", peer.rx_bytes))
			send(fmt.Sprintf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval))
			for _, ip := range device.routingTable.AllowedIPs(peer) {
				send("allowed_ip=" + ip.String())
			}
		}()
	}

	// send lines

	for _, line := range lines {
		device.log.Debug.Println("config:", line)
		_, err := socket.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func ipcSetOperation(device *Device, socket *bufio.ReadWriter) *IPCError {

	scanner := bufio.NewScanner(socket)

	device.mutex.Lock()
	defer device.mutex.Unlock()

	for scanner.Scan() {
		var key string
		var value string
		var peer *Peer

		// Parse line

		line := scanner.Text()
		if line == "\n" {
			break
		}
		fmt.Println(line)
		n, err := fmt.Sscanf(line, "%s=%s\n", &key, &value)
		if n != 2 || err != nil {
			fmt.Println(err, n)
			return &IPCError{Code: ipcErrorNoKeyValue}
		}

		switch key {

		/* Interface configuration */

		case "private_key":
			if value == "" {
				device.privateKey = NoisePrivateKey{}
			} else {
				err := device.privateKey.FromHex(value)
				if err != nil {
					return &IPCError{Code: ipcErrorInvalidPrivateKey}
				}
			}

		case "listen_port":
			_, err := fmt.Sscanf(value, "%ud", &device.address.Port)
			if err != nil {
				return &IPCError{Code: ipcErrorInvalidPort}
			}

		case "fwmark":
			panic(nil) // not handled yet

		case "public_key":
			var pubKey NoisePublicKey
			err := pubKey.FromHex(value)
			if err != nil {
				return &IPCError{Code: ipcErrorInvalidPublicKey}
			}
			found, ok := device.peers[pubKey]
			if ok {
				peer = found
			} else {
				peer = device.NewPeer(pubKey)
			}

		case "replace_peers":
			if key == "true" {
				device.RemoveAllPeers()
			} else if key == "false" {
			} else {
				return &IPCError{Code: ipcErrorInvalidValue}
			}

		default:
			/* Peer configuration */

			if peer == nil {
				return &IPCError{Code: ipcErrorNoPeer}
			}

			switch key {

			case "remove":
				peer.mutex.Lock()
				// device.RemovePeer(peer.publicKey)
				peer = nil

			case "preshared_key":
				err := func() error {
					peer.mutex.Lock()
					defer peer.mutex.Unlock()
					return peer.handshake.presharedKey.FromHex(value)
				}()
				if err != nil {
					return &IPCError{Code: ipcErrorInvalidPublicKey}
				}

			case "endpoint":
				ip := net.ParseIP(value)
				if ip == nil {
					return &IPCError{Code: ipcErrorInvalidIPAddress}
				}
				peer.mutex.Lock()
				// peer.endpoint = ip FIX
				peer.mutex.Unlock()

			case "persistent_keepalive_interval":
				secs, err := strconv.ParseInt(value, 10, 64)
				if secs < 0 || err != nil {
					return &IPCError{Code: ipcErrorInvalidValue}
				}
				peer.mutex.Lock()
				peer.persistentKeepaliveInterval = time.Duration(secs) * time.Second
				peer.mutex.Unlock()

			case "replace_allowed_ips":
				if key == "true" {
					device.routingTable.RemovePeer(peer)
				} else if key == "false" {
				} else {
					return &IPCError{Code: ipcErrorInvalidValue}
				}

			case "allowed_ip":
				_, network, err := net.ParseCIDR(value)
				if err != nil {
					return &IPCError{Code: ipcErrorInvalidValue}
				}
				ones, _ := network.Mask.Size()
				device.routingTable.Insert(network.IP, uint(ones), peer)

			/* Invalid key */

			default:
				return &IPCError{Code: ipcErrorInvalidKey}
			}
		}
	}

	return nil
}

func ipcListen(device *Device, socket io.ReadWriter) error {

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	defer buffered.Flush()

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return err
		}
		log.Println(op)

		switch op {

		case "set=1\n":
			err := ipcSetOperation(device, buffered)
			if err != nil {
				fmt.Fprintf(buffered, "errno=%d\n\n", err.ErrorCode())
				return err
			} else {
				fmt.Fprintf(buffered, "errno=0\n\n")
			}
			buffered.Flush()

		case "get=1\n":
			err := ipcGetOperation(device, buffered)
			if err != nil {
				fmt.Fprintf(buffered, "errno=1\n\n") // fix
				return err
			} else {
				fmt.Fprintf(buffered, "errno=0\n\n")
			}
			buffered.Flush()

		case "\n":
		default:
			return errors.New("handle this please")
		}
	}

}
