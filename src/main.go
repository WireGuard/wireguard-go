package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	l, err := net.Listen("unix", "/var/run/wireguard/wg0.sock")
	if err != nil {
		log.Fatal("listen error:", err)
	}

	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		var dev Device
		go func(conn net.Conn) {
			err := ipcListen(&dev, conn)
			fmt.Println(err)
		}(fd)
	}

}
