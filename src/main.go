package main

import (
	"log"
	"net"
)

/*
 *
 * TODO: Fix logging
 */

func main() {
	// Open TUN device

	// TODO: Fix capabilities

	tun, err := CreateTUN("test0")
	log.Println(tun, err)
	if err != nil {
		return
	}

	device := NewDevice(tun)

	// Start configuration lister

	l, err := net.Listen("unix", "/var/run/wireguard/wg0.sock")
	if err != nil {
		log.Fatal("listen error:", err)
	}

	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go func(conn net.Conn) {
			err := ipcListen(device, conn)
			log.Println(err)
		}(fd)
	}
}
