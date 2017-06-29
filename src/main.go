package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

/* TODO: Fix logging
 * TODO: Fix daemon
 */

func main() {

	if len(os.Args) != 2 {
		return
	}
	deviceName := os.Args[1]

	// Open TUN device

	// TODO: Fix capabilities

	tun, err := CreateTUN(deviceName)
	log.Println(tun, err)
	if err != nil {
		return
	}

	device := NewDevice(tun)

	// Start configuration lister

	socketPath := fmt.Sprintf("/var/run/wireguard/%s.sock", deviceName)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go ipcHandle(device, conn)
	}
}
