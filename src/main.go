package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD  = "WG_TUN_FD"
	ENV_WG_UAPI_FD = "WG_UAPI_FD"
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

	// open TUN device (or use supplied fd)

	tun, err := func() (TUNDevice, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return CreateTUN(interfaceName)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return CreateTUNFromFile(interfaceName, file)
	}()

	if err != nil {
		logger.Error.Println("Failed to create TUN device:", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()

	if err != nil {
		logger.Error.Println("UAPI listen error:", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		attr := &os.ProcAttr{
			Files: []*os.File{
				nil, // stdin
				nil, // stdout
				nil, // stderr
				tun.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}
		err = Daemonize(attr)
		if err != nil {
			logger.Error.Println("Failed to daemonize:", err)
			os.Exit(ExitSetupFailed)
		}
		return
	}

	// increase number of go workers (for Go <1.5)

	runtime.GOMAXPROCS(runtime.NumCPU())

	// create wireguard device

	device := NewDevice(tun, logger)

	logger.Info.Println("Device started")

	// start uapi listener

	errs := make(chan error)
	term := make(chan os.Signal)

	uapi, err := UAPIListen(interfaceName, fileUAPI)

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
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Info.Println("Shutting down")
}
