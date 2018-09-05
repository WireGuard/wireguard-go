/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"git.zx2c4.com/wireguard-go/tun"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
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
	if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
		return
	}

	shouldQuit := false

	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "W   This is alpha software. It will very likely not   G")
	fmt.Fprintln(os.Stderr, "W   do what it is supposed to do, and things may go   G")
	fmt.Fprintln(os.Stderr, "W   horribly wrong. You have been warned. Proceed     G")
	fmt.Fprintln(os.Stderr, "W   at your own risk.                                 G")
	if runtime.GOOS == "linux" {
		shouldQuit = os.Getenv("WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD") != "1"

		fmt.Fprintln(os.Stderr, "W                                                     G")
		fmt.Fprintln(os.Stderr, "W   Furthermore, you are running this software on a   G")
		fmt.Fprintln(os.Stderr, "W   Linux kernel, which is probably unnecessary and   G")
		fmt.Fprintln(os.Stderr, "W   foolish. This is because the Linux kernel has     G")
		fmt.Fprintln(os.Stderr, "W   built-in first class support for WireGuard, and   G")
		fmt.Fprintln(os.Stderr, "W   this support is much more refined than this       G")
		fmt.Fprintln(os.Stderr, "W   program. For more information on installing the   G")
		fmt.Fprintln(os.Stderr, "W   kernel module, please visit:                      G")
		fmt.Fprintln(os.Stderr, "W           https://www.wireguard.com/install         G")
		if shouldQuit {
			fmt.Fprintln(os.Stderr, "W                                                     G")
			fmt.Fprintln(os.Stderr, "W   If you still want to use this program, against    G")
			fmt.Fprintln(os.Stderr, "W   the sage advice here, please first export this    G")
			fmt.Fprintln(os.Stderr, "W   environment variable:                             G")
			fmt.Fprintln(os.Stderr, "W   WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1    G")
		}
	}
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")

	if shouldQuit {
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", WireGuardGoVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

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

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
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
		case "silent":
			return LogLevelSilent
		}
		return LogLevelInfo
	}()

	// open TUN device (or use supplied fd)

	tun, err := func() (tun.TUNDevice, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Info.Println("Starting wireguard-go version", WireGuardGoVersion)

	logger.Debug.Println("Debug log enabled")

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
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != LogLevelSilent {
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

	device := NewDevice(tun, logger)

	logger.Info.Println("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := UAPIListen(interfaceName, fileUAPI)
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
			go ipcHandle(device, conn)
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
