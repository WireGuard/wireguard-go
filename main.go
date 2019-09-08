// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

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
	fmt.Printf("usage:\n")
	fmt.Printf("%s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func warning() {
	if runtime.GOOS != "linux" || os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
		return
	}

	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "W   You are running this software on a Linux kernel,  G")
	fmt.Fprintln(os.Stderr, "W   which is probably unnecessary and misguided. This G")
	fmt.Fprintln(os.Stderr, "W   is because the Linux kernel has built-in first    G")
	fmt.Fprintln(os.Stderr, "W   class support for WireGuard, and this support is  G")
	fmt.Fprintln(os.Stderr, "W   much more refined than this slower userspace      G")
	fmt.Fprintln(os.Stderr, "W   implementation. For more information on           G")
	fmt.Fprintln(os.Stderr, "W   installing the kernel module, please visit:       G")
	fmt.Fprintln(os.Stderr, "W           https://www.wireguard.com/install         G")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", device.WireGuardGoVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

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

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "debug":
			return device.LogLevelDebug
		case "info":
			return device.LogLevelInfo
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelInfo
	}()

	// open TUN device (or use supplied fd)

	tun, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = syscall.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)

	logger.Debug.Println("Debug log enabled")

	if err != nil {
		logger.Error.Println("Failed to create TUN device:", err)
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
		logger.Error.Println("UAPI listen error:", err)
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
				tun.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Error.Println("Failed to determine executable:", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Error.Println("Failed to daemonize:", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tun, logger)

	logger.Info.Println("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
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

	logger.Info.Println("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, syscall.SIGTERM)
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
