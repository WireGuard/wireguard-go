package main

import (
	"log"
	"os"
	"runtime"
)

func main() {

	// parse arguments

	var foreground bool
	var interfaceName string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			return
		}
		interfaceName = os.Args[2]

	default:
		foreground = false
		if len(os.Args) != 2 {
			return
		}
		interfaceName = os.Args[1]
	}

	// daemonize the process

	if !foreground {
		err := Daemonize()
		if err != nil {
			log.Println("Failed to daemonize:", err)
		}
		return
	}

	// increase number of go workers (for Go <1.5)

	runtime.GOMAXPROCS(runtime.NumCPU())

	// open TUN device

	tun, err := CreateTUN(interfaceName)
	if err != nil {
		log.Println("Failed to create tun device:", err)
		return
	}

	// create wireguard device

	device := NewDevice(tun, LogLevelDebug)

	logInfo := device.log.Info
	logError := device.log.Error
	logInfo.Println("Starting device")

	// start configuration lister

	uapi, err := NewUAPIListener(interfaceName)
	if err != nil {
		logError.Fatal("UAPI listen error:", err)
	}
	defer uapi.Close()

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				logError.Fatal("UAPI accept error:", err)
			}
			go ipcHandle(device, conn)
		}
	}()

	device.Wait()
}
