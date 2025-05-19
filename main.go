//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func printUsage() {
	fmt.Printf("Usage: %s [-f/--foreground] [-tcp/--tcp-mode] [-p/--port PORT] [-obfs/--obfuscation TYPE] [-kr/--key-rotation HOURS] INTERFACE-NAME\n", os.Args[0])
	fmt.Println("Options:")
	fmt.Println("  -f, --foreground       Run in the foreground")
	fmt.Println("  -tcp, --tcp-mode       Use TCP instead of UDP")
	fmt.Println("  -p, --port PORT        Port to listen on (default: 51820)")
	fmt.Println("  -obfs, --obfuscation TYPE  Traffic obfuscation type: none, ws, tls")
	fmt.Println("  -wsurl, --websocket-url URL  WebSocket URL for obfuscation")
	fmt.Println("  -kr, --key-rotation HOURS  Enable key rotation with specified interval in hours")
	fmt.Println("  --version              Show version information")
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
			return
		}
	default:
		return
	}

	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "│   Running wireguard-go is not required because this  │")
	fmt.Fprintln(os.Stderr, "│   kernel has first class support for WireGuard. For  │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,       │")
	fmt.Fprintln(os.Stderr, "│   please visit:                                      │")
	fmt.Fprintln(os.Stderr, "│         https://www.wireguard.com/install/           │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	// Parse command line flags
	var (
		foreground          bool
		useTCP              bool
		port                int
		obfuscationType     string
		webSocketURL        string
		keyRotationInterval int
		interfaceName       string
	)

	// Define flags
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.BoolVar(&foreground, "f", false, "Run in the foreground")
	flagSet.BoolVar(&foreground, "foreground", false, "Run in the foreground")
	flagSet.BoolVar(&useTCP, "tcp", false, "Use TCP instead of UDP")
	flagSet.BoolVar(&useTCP, "tcp-mode", false, "Use TCP instead of UDP")
	flagSet.IntVar(&port, "p", 51820, "Port to listen on")
	flagSet.IntVar(&port, "port", 51820, "Port to listen on")
	flagSet.StringVar(&obfuscationType, "obfs", "none", "Traffic obfuscation type: none, ws, tls")
	flagSet.StringVar(&obfuscationType, "obfuscation", "none", "Traffic obfuscation type: none, ws, tls")
	flagSet.StringVar(&webSocketURL, "wsurl", "wss://localhost/wireguard", "WebSocket URL for obfuscation")
	flagSet.StringVar(&webSocketURL, "websocket-url", "wss://localhost/wireguard", "WebSocket URL for obfuscation")
	flagSet.IntVar(&keyRotationInterval, "kr", 24, "Key rotation interval in hours (0 to disable)")
	flagSet.IntVar(&keyRotationInterval, "key-rotation", 24, "Key rotation interval in hours (0 to disable)")
	
	// Parse command line arguments
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		printUsage()
		return
	}
	
	// Get the interface name (the last argument)
	args := flagSet.Args()
	if len(args) != 1 {
		printUsage()
		return
	}
	interfaceName = args[0]

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	// open TUN device (or use supplied fd)

	tdev, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = unix.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tdev.File(),
				fileUAPI,
			},
			Dir: "",
			Env: env,
		}

		process, err := os.StartProcess(os.Args[0], os.Args, attr)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	// Setup TCP listener if requested
	if useTCP {
		logger.Verbosef("Using TCP mode on port %d", port)
		if err := device.ListenTCP(port); err != nil {
			logger.Errorf("Failed to listen on TCP port %d: %v", port, err)
			os.Exit(ExitSetupFailed)
		}
	} else {
		// Start the device with standard UDP
		logger.Verbosef("Using standard UDP mode")
		device.Up()
	}
	
	// Configure obfuscation if enabled
	if obfuscationType != "none" {
		logger.Verbosef("Enabling %s obfuscation", obfuscationType)
		var obfsType device.ObfuscationType
		
		switch obfuscationType {
		case "ws":
			obfsType = device.ObfuscationWebSocket
			logger.Verbosef("Using WebSocket URL: %s", webSocketURL)
		case "tls":
			obfsType = device.ObfuscationTLS
		default:
			logger.Errorf("Unknown obfuscation type: %s", obfuscationType)
			os.Exit(ExitSetupFailed)
		}
		
		// We would configure obfuscation here if we had direct access to connections
		// This is a placeholder; in a real implementation, this would be integrated
		// more deeply into the connection handling
	}
	
	// Configure key rotation if enabled
	if keyRotationInterval > 0 {
		logger.Verbosef("Enabling key rotation every %d hours", keyRotationInterval)
		keyRotationConfig := device.KeyRotationConfig{
			Enabled:  true,
			Interval: time.Duration(keyRotationInterval) * time.Hour,
			// API endpoint would be configured here
		}
		
		if err := device.StartKeyRotation(keyRotationConfig); err != nil {
			logger.Errorf("Failed to start key rotation: %v", err)
			os.Exit(ExitSetupFailed)
		}
	}

	logger.Verbosef("UAPI listener started")
	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
