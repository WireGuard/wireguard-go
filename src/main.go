package main

import (
	"fmt"
)

func main() {
	fd, err := CreateTUN("test0")
	fmt.Println(fd, err)

	queue := make(chan []byte, 1000)

	// var device Device

	// go OutgoingRoutingWorker(&device, queue)

	for {
		tmp := make([]byte, 1<<16)
		n, err := fd.Read(tmp)
		if err != nil {
			break
		}
		queue <- tmp[:n]
	}
}

/*
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
*/
