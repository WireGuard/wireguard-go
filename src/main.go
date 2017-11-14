package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
)

const (
	EnvWGTunFD = "WG_TUN_FD"
)

func printUsage() {
	fmt.Printf("usage:\n")
	fmt.Printf("%s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func main() {

	// parse arguments

	var foreground bool
	var interfaceName string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		interfaceName = os.Args[2]

	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		interfaceName = os.Args[1]
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "debug":
			return LogLevelDebug
		case "info":
			return LogLevelInfo
		case "error":
			return LogLevelError
		}
		return LogLevelInfo
	}()

	logger := NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Debug.Println("Debug log enabled")

	// open TUN device

	tun, err := func() (TUNDevice, error) {
		tunFdStr := os.Getenv(EnvWGTunFD)
		if tunFdStr == "" {
			return CreateTUN(interfaceName)
		}

		// construct tun device from supplied FD

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "/dev/net/tun")
		return CreateTUNFromFile(interfaceName, file)
	}()

	if err != nil {
		logger.Error.Println("Failed to create TUN device:", err)
	}

	// daemonize the process

	if !foreground {
		env := os.Environ()
		_, ok := os.LookupEnv(EnvWGTunFD)
		if !ok {
			kvp := fmt.Sprintf("%s=3", EnvWGTunFD)
			env = append(env, kvp)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				nil, // stdin
				nil, // stdout
				nil, // stderr
				tun.File(),
			},
			Dir: ".",
			Env: env,
		}
		err = Daemonize(attr)
		if err != nil {
			logger.Error.Println("Failed to daemonize:", err)
		}
		return
	}

	// increase number of go workers (for Go <1.5)

	runtime.GOMAXPROCS(runtime.NumCPU())

	// create wireguard device

	device := NewDevice(tun, logger)
	logger.Info.Println("Device started")

	// start configuration lister

	uapi, err := NewUAPIListener(interfaceName)
	if err != nil {
		logger.Error.Println("UAPI listen error:", err)
		return
	}

	errs := make(chan error)
	term := make(chan os.Signal)
	wait := device.WaitChannel()

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go ipcHandle(device, conn)
		}
	}()

	logger.Info.Println("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, os.Kill)
	signal.Notify(term, os.Interrupt)

	select {
	case <-wait:
	case <-term:
	case <-errs:
	}

	// clean up UAPI bind

	uapi.Close()

	logger.Info.Println("Shutting down")
}
