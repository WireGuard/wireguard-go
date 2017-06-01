package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

/* todo : use real error code
 * Many of which will be the same
 */
const (
	ipcErrorNoPeer            = 0
	ipcErrorNoKeyValue        = 1
	ipcErrorInvalidKey        = 2
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

// Writes the configuration to the socket
func ipcGetOperation(socket *bufio.ReadWriter, dev *Device) {

}

// Creates new config, from old and socket message
func ipcSetOperation(dev *Device, socket *bufio.ReadWriter) *IPCError {

	scanner := bufio.NewScanner(socket)

	dev.mutex.Lock()
	defer dev.mutex.Unlock()

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
				dev.privateKey = NoisePrivateKey{}
			} else {
				err := dev.privateKey.FromHex(value)
				if err != nil {
					return &IPCError{Code: ipcErrorInvalidPrivateKey}
				}
			}

		case "listen_port":
			_, err := fmt.Sscanf(value, "%ud", &dev.listenPort)
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
			found, ok := dev.peers[pubKey]
			if ok {
				peer = found
			} else {
				newPeer := &Peer{
					publicKey: pubKey,
				}
				peer = newPeer
				dev.peers[pubKey] = newPeer
			}

		case "replace_peers":
			if key == "true" {
				dev.RemoveAllPeers()
			}
			// todo: else fail

		default:
			/* Peer configuration */

			if peer == nil {
				return &IPCError{Code: ipcErrorNoPeer}
			}

			switch key {

			case "remove":
				peer.mutex.Lock()
				dev.RemovePeer(peer.publicKey)
				peer = nil

			case "preshared_key":
				err := func() error {
					peer.mutex.Lock()
					defer peer.mutex.Unlock()
					return peer.presharedKey.FromHex(value)
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
				peer.endpoint = ip
				peer.mutex.Unlock()

			case "persistent_keepalive_interval":
				func() {
					peer.mutex.Lock()
					defer peer.mutex.Unlock()
				}()

			case "replace_allowed_ips":
				// remove peer from trie

			case "allowed_ip":

			/* Invalid key */

			default:
				return &IPCError{Code: ipcErrorInvalidKey}
			}
		}
	}

	return nil
}

func ipcListen(dev *Device, socket io.ReadWriter) error {

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return err
		}
		log.Println(op)

		switch op {

		case "set=1\n":
			err := ipcSetOperation(dev, buffered)
			if err != nil {
				fmt.Fprintf(buffered, "errno=%d\n", err.ErrorCode())
				return err
			} else {
				fmt.Fprintf(buffered, "errno=0\n")
			}
			buffered.Flush()

		case "get=1\n":

		default:
			return errors.New("handle this please")
		}
	}

}
