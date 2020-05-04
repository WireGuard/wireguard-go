/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// Test the following topology:
//
// ┌─────────────────────┐   ┌──────────────────────────────────┐   ┌─────────────────────┐
// │  $netns1 namespace  │   │         $netns0 namespace        │   │  $netns2 namespace  │
// │                     │   │                                  │   │                     │
// │┌────────┐           │   │            ┌────────┐            │   │           ┌────────┐│
// ││  $wg1  │───────────┼───┼────────────│   lo   │────────────┼───┼───────────│  $wg2  ││
// │├────────┴──────────┐│   │    ┌───────┴────────┴────────┐   │   │┌──────────┴────────┤│
// ││192.168.241.1/24   ││   │    │(ns1)         (ns2)      │   │   ││192.168.241.2/24   ││
// ││fd00::1/24         ││   │    │127.0.0.1:1   127.0.0.1:2│   │   ││fd00::2/24         ││
// │└───────────────────┘│   │    │[::]:1        [::]:2     │   │   │└───────────────────┘│
// └─────────────────────┘   │    └─────────────────────────┘   │   └─────────────────────┘
//                           └──────────────────────────────────┘
//
// Note: $netns0 is the endpoint for the wg1 interfaces in $netns1 and $netns2.
// See https://www.wireguard.com/netns/ for further details.
func TestNS(t *testing.T) {
	checkRootOnLinux(t)

	mustsh := func(t *testing.T, cmd string, arg, stdin string) string {
		t.Helper()
		sh := exec.Command(cmd, arg)
		if stdin != "" {
			sh.Stdin = strings.NewReader(stdin)
		}
		out, err := sh.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v", cmd, arg, err)
		}
		return strings.TrimSpace(string(out))
	}

	netns := func(num int) string {
		return fmt.Sprintf("wg-test-%d-%d", os.Getpid(), num)
	}
	wg := func(num int) string {
		return fmt.Sprintf("wg%d%d", 1, num)
	}
	key1 := mustsh(t, "wg", "genkey", "")
	key2 := mustsh(t, "wg", "genkey", "")
	script := scriptScope{
		vars: map[string]string{
			"netns0": netns(0),
			"netns1": netns(1),
			"netns2": netns(2),
			"wg1":    wg(1),
			"wg2":    wg(2),
			"key1":   key1,
			"key2":   key2,
			"pub1":   mustsh(t, "wg", "pubkey", key1),
			"pub2":   mustsh(t, "wg", "pubkey", key2),
			"psk":    mustsh(t, "wg", "genpsk", ""),
		},
	}

	// TODO: orig_message_cost

	script.run(t, "setup namespace", `
ip netns del $netns0 2>/dev/null || true
ip netns del $netns1 2>/dev/null || true
ip netns del $netns2 2>/dev/null || true
ip netns add $netns0
ip netns add $netns1
ip netns add $netns2
ip0 link set up dev lo
`)

	wg1cmd := startWG(t, netns(0), "$wg1", wg(1))
	defer wg1cmd.Process.Kill()
	script.run(t, "setup $wg1", `ip0 link set $wg1 netns $netns1`)

	wg2cmd := startWG(t, netns(0), "$wg2", wg(2))
	defer wg2cmd.Process.Kill()
	script.run(t, "setup $wg2", `ip0 link set $wg2 netns $netns2`)

	script.run(t, "configure", `
ip1 addr add 192.168.241.1/24 dev $wg1
ip1 addr add fd00::1/24 dev $wg1

ip2 addr add 192.168.241.2/24 dev $wg2
ip2 addr add fd00::2/24 dev $wg2

n0 wg set $wg1 \
	private-key <(echo "$key1") \
	listen-port 10000 \
	peer "$pub2" \
		preshared-key <(echo "$psk") \
		allowed-ips 192.168.241.2/32,fd00::2/128
n0 wg set $wg2 \
	private-key <(echo "$key2") \
	listen-port 20000 \
	peer "$pub1" \
		preshared-key <(echo "$psk") \
		allowed-ips 192.168.241.1/32,fd00::1/128

ip1 link set up dev $wg1
ip2 link set up dev $wg2

sleep 1

# Test using IPv4 as outer transport
#n0 wg set $wg1 peer "$pub2" endpoint 127.0.0.1:20000
n0 wg set $wg2 peer "$pub1" endpoint 127.0.0.1:10000

n0 wg showconf $wg1
n0 wg showconf $wg2
`)

	time.Sleep(1 * time.Second)

	// TODO: counter test

	script.run(t, "ping test", `
# Ping over IPv4
n2 ping -c 10 -f -W 1 192.168.241.1
n1 ping -c 10 -f -W 1 192.168.241.2

# Ping over IPv6
n2 ping6 -c 10 -f -W 1 fd00::1
n1 ping6 -c 10 -f -W 1 fd00::2
`)

}

// TODO
// TestSticky tests sticky sockets work.
//
// We start with this topology:
//
// ┌────────────────────────────────────────┐    ┌────────────────────────────────────────┐
// │           $netns1 namespace            │    │           $netns2 namespace            │
// │                                        │    │                                        │
// │  ┌──────┐            ┌─────┐           │    │  ┌─────┐            ┌──────┐           │
// │  │ $wg1 |────────────│veth1│───────────┼────┼──│veth2│────────────│ $wg2 │           │
// │  ├──────┴─────────┐  ├─────┴──────────┐│    │  ├─────┴──────────┐ ├──────┴─────────┐ │
// │  │192.168.241.1/24│  │10.0.0.1/24     ││    │  │10.0.0.2/24     │ │192.168.241.2/24│ │
// │  │fd00::1/24      │  │fd00:aa::1/96   ││    │  │fd00:aa::2/96   │ │fd00::2/24      │ │
// │  └────────────────┘  └────────────────┘│    │  └────────────────┘ └────────────────┘ │
// └────────────────────────────────────────┘    └────────────────────────────────────────┘
// TODO

// startWG starts wireguard-go by forking the test process and executing
// TestChild with a magic env variable. We do this instead of starting
// wireguard directly in the process because we want to run under a
// linux namespace.
//
// We cannot use setns(2) for this, because the syscall is per-thread.
// The initial tun binding works, but then device.NewDevice creates
// goroutines which run on other OS threads where setns(2) wasn't applied.
func startWG(t *testing.T, netns, dispname, name string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", netns, os.Args[0], "-test.run=TestChild$")
	cmd.Env = append([]string{
		"TEST_WG_CHILD=" + name,
	}, os.Environ()...)
	cmd.Stdout = logWriter{logf: func(format string, args ...interface{}) {
		t.Logf(dispname+": "+format, args...)
	}}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second) // eww TODO
	return cmd
}

// TestChild is a fake test. See startWG for details.
func TestChild(t *testing.T) {
	name := os.Getenv("TEST_WG_CHILD")
	if name == "" {
		t.Skip("TestChild is a fake test used to start the tun $TEST_WG_CHILD, skipping")
	}
	log.Printf("starting wireguard-go on tun %s", name)

	tun, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	d := device.NewDevice(tun, device.NewLogger(device.LogLevelInfo, "")) // TODO: LogLevelDebug option

	fileUAPI, err := ipc.UAPIOpen(name)
	if err != nil {
		t.Fatal(err)
	}
	uapi, err := ipc.UAPIListen(name, fileUAPI)
	if err != nil {
		t.Fatal(err)
	}
	for {
		conn, err := uapi.Accept()
		if err != nil {
			break
		}
		go d.IpcHandle(conn)
	}
	// TODO: listen for a user signal to know shutdown is clean
	os.Exit(0)
}

type scriptScope struct {
	vars map[string]string
}

func (s scriptScope) run(t *testing.T, name, script string) {
	const header = `#!/bin/sh
set -e

export WG_HIDE_KEYS=never

n0() { ip netns exec $netns0 "$@"; }
n1() { ip netns exec $netns1 "$@"; }
n2() { ip netns exec $netns2 "$@"; }
ip0() { ip -n $netns0 "$@"; }
ip1() { ip -n $netns1 "$@"; }
ip2() { ip -n $netns2 "$@"; }

`

	buf := new(bytes.Buffer)
	buf.WriteString(header)
	var varNames []string
	for name := range s.vars {
		varNames = append(varNames, name)
	}
	sort.Strings(varNames)
	for _, name := range varNames {
		fmt.Fprintf(buf, "%s=%q\n", name, s.vars[name])
	}
	buf.WriteString("set -x\n")
	buf.WriteString(script)

	sh := exec.Command("/bin/bash")
	sh.Stdin = buf
	sh.Stdout = logWriter{logf: t.Logf}
	sh.Stderr = logWriter{logf: t.Logf}
	if err := sh.Run(); err != nil {
		t.Fatalf("%s failed: %v", name, err)
	}
}

func checkRootOnLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("SKIPPING test, requires GOOS=linux")
	}
	if os.Getuid() != 0 {
		t.Skip("SKIPPING test, requires root")
	}
}

func logger(name string, logf func(format string, args ...interface{})) *device.Logger {
	w := logWriter{logf: logf}
	return &device.Logger{
		Debug: log.New(ioutil.Discard, "DEBUG("+name+"): ", 0),
		Info:  log.New(w, "INFO("+name+"): ", 0),
		Error: log.New(w, "ERROR("+name+"): ", 0),
	}
}

type logWriter struct {
	logf func(format string, args ...interface{})
}

func (lw logWriter) Write(b []byte) (int, error) {
	lw.logf("%s", b)
	return len(b), nil
}
