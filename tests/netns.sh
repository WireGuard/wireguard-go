#!/bin/bash

# Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# This script tests the below topology:
#
# ┌─────────────────────┐   ┌──────────────────────────────────┐   ┌─────────────────────┐
# │   $ns1 namespace    │   │          $ns0 namespace          │   │   $ns2 namespace    │
# │                     │   │                                  │   │                     │
# │┌────────┐           │   │            ┌────────┐            │   │           ┌────────┐│
# ││  wg1   │───────────┼───┼────────────│   lo   │────────────┼───┼───────────│  wg2   ││
# │├────────┴──────────┐│   │    ┌───────┴────────┴────────┐   │   │┌──────────┴────────┤│
# ││192.168.241.1/24   ││   │    │(ns1)         (ns2)      │   │   ││192.168.241.2/24   ││
# ││fd00::1/24         ││   │    │127.0.0.1:1   127.0.0.1:2│   │   ││fd00::2/24         ││
# │└───────────────────┘│   │    │[::]:1        [::]:2     │   │   │└───────────────────┘│
# └─────────────────────┘   │    └─────────────────────────┘   │   └─────────────────────┘
#                           └──────────────────────────────────┘
#
# After the topology is prepared we run a series of TCP/UDP iperf3 tests between the
# wireguard peers in $ns1 and $ns2. Note that $ns0 is the endpoint for the wg1
# interfaces in $ns1 and $ns2. See https://www.wireguard.com/netns/ for further
# details on how this is accomplished.

# This code is ported to the WireGuard-Go directly from the kernel project.
#
# Please ensure that you have installed the newest version of the WireGuard
# tools from the WireGuard project and before running these tests as:
#
# ./netns.sh <path to wireguard-go>

set -e

exec 3>&1
export WG_HIDE_KEYS=never
netns0="wg-test-$$-0"
netns1="wg-test-$$-1"
netns2="wg-test-$$-2"
program=$1
export LOG_LEVEL="verbose"

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
n0() { pretty 0 "$*"; maybe_exec ip netns exec $netns0 "$@"; }
n1() { pretty 1 "$*"; maybe_exec ip netns exec $netns1 "$@"; }
n2() { pretty 2 "$*"; maybe_exec ip netns exec $netns2 "$@"; }
ip0() { pretty 0 "ip $*"; ip -n $netns0 "$@"; }
ip1() { pretty 1 "ip $*"; ip -n $netns1 "$@"; }
ip2() { pretty 2 "ip $*"; ip -n $netns2 "$@"; }
sleep() { read -t "$1" -N 0 || true; }
waitiperf() { pretty "${1//*-}" "wait for iperf:5201"; while [[ $(ss -N "$1" -tlp 'sport = 5201') != *iperf3* ]]; do sleep 0.1; done; }
waitncatudp() { pretty "${1//*-}" "wait for udp:1111"; while [[ $(ss -N "$1" -ulp 'sport = 1111') != *ncat* ]]; do sleep 0.1; done; }
waitiface() { pretty "${1//*-}" "wait for $2 to come up"; ip netns exec "$1" bash -c "while [[ \$(< \"/sys/class/net/$2/operstate\") != up ]]; do read -t .1 -N 0 || true; done;"; }

cleanup() {
    set +e
    exec 2>/dev/null
    printf "$orig_message_cost" > /proc/sys/net/core/message_cost
    ip0 link del dev wg1
    ip1 link del dev wg1
    ip2 link del dev wg1
    local to_kill="$(ip netns pids $netns0) $(ip netns pids $netns1) $(ip netns pids $netns2)"
    [[ -n $to_kill ]] && kill $to_kill
    pp ip netns del $netns1
    pp ip netns del $netns2
    pp ip netns del $netns0
    exit
}

orig_message_cost="$(< /proc/sys/net/core/message_cost)"
trap cleanup EXIT
printf 0 > /proc/sys/net/core/message_cost

ip netns del $netns0 2>/dev/null || true
ip netns del $netns1 2>/dev/null || true
ip netns del $netns2 2>/dev/null || true
pp ip netns add $netns0
pp ip netns add $netns1
pp ip netns add $netns2
ip0 link set up dev lo

# ip0 link add dev wg1 type wireguard
n0 $program wg1
ip0 link set wg1 netns $netns1

# ip0 link add dev wg1 type wireguard
n0 $program wg2
ip0 link set wg2 netns $netns2

key1="$(pp wg genkey)"
key2="$(pp wg genkey)"
pub1="$(pp wg pubkey <<<"$key1")"
pub2="$(pp wg pubkey <<<"$key2")"
psk="$(pp wg genpsk)"
[[ -n $key1 && -n $key2 && -n $psk ]]

configure_peers() {

    ip1 addr add 192.168.241.1/24 dev wg1
    ip1 addr add fd00::1/24 dev wg1

    ip2 addr add 192.168.241.2/24 dev wg2
    ip2 addr add fd00::2/24 dev wg2

    n0 wg set wg1 \
        private-key <(echo "$key1") \
        listen-port 10000 \
        peer "$pub2" \
            preshared-key <(echo "$psk") \
            allowed-ips 192.168.241.2/32,fd00::2/128
    n0 wg set wg2 \
        private-key <(echo "$key2") \
        listen-port 20000 \
        peer "$pub1" \
            preshared-key <(echo "$psk") \
            allowed-ips 192.168.241.1/32,fd00::1/128

    n0 wg showconf wg1
    n0 wg showconf wg2

    ip1 link set up dev wg1
    ip2 link set up dev wg2
    sleep 1
}
configure_peers

tests() {
    # Ping over IPv4
    n2 ping -c 10 -f -W 1 192.168.241.1
    n1 ping -c 10 -f -W 1 192.168.241.2

    # Ping over IPv6
    n2 ping6 -c 10 -f -W 1 fd00::1
    n1 ping6 -c 10 -f -W 1 fd00::2

    # TCP over IPv4
    n2 iperf3 -s -1 -B 192.168.241.2 &
    waitiperf $netns2
    n1 iperf3 -Z -n 1G -c 192.168.241.2

    # TCP over IPv6
    n1 iperf3 -s -1 -B fd00::1 &
    waitiperf $netns1
    n2 iperf3 -Z -n 1G -c fd00::1

    # UDP over IPv4
    n1 iperf3 -s -1 -B 192.168.241.1 &
    waitiperf $netns1
    n2 iperf3 -Z -n 1G -b 0 -u -c 192.168.241.1

    # UDP over IPv6
    n2 iperf3 -s -1 -B fd00::2 &
    waitiperf $netns2
    n1 iperf3 -Z -n 1G -b 0 -u -c fd00::2
}

[[ $(ip1 link show dev wg1) =~ mtu\ ([0-9]+) ]] && orig_mtu="${BASH_REMATCH[1]}"
big_mtu=$(( 34816 - 1500 + $orig_mtu ))

# Test using IPv4 as outer transport
n0 wg set wg1 peer "$pub2" endpoint 127.0.0.1:20000
n0 wg set wg2 peer "$pub1" endpoint 127.0.0.1:10000

# Before calling tests, we first make sure that the stats counters are working
n2 ping -c 10 -f -W 1 192.168.241.1
{ read _; read _; read _; read rx_bytes _; read _; read tx_bytes _; } < <(ip2 -stats link show dev wg2)
ip2 -stats link show dev wg2
n0 wg show
[[ $rx_bytes -ge 840 && $tx_bytes -ge 880 && $rx_bytes -lt 2500 && $rx_bytes -lt 2500 ]]
echo "counters working"
tests
ip1 link set wg1 mtu $big_mtu
ip2 link set wg2 mtu $big_mtu
tests

ip1 link set wg1 mtu $orig_mtu
ip2 link set wg2 mtu $orig_mtu

# Test using IPv6 as outer transport
n0 wg set wg1 peer "$pub2" endpoint [::1]:20000
n0 wg set wg2 peer "$pub1" endpoint [::1]:10000
tests
ip1 link set wg1 mtu $big_mtu
ip2 link set wg2 mtu $big_mtu
tests

ip1 link set wg1 mtu $orig_mtu
ip2 link set wg2 mtu $orig_mtu

# Test using IPv4 that roaming works
ip0 -4 addr del 127.0.0.1/8 dev lo
ip0 -4 addr add 127.212.121.99/8 dev lo
n0 wg set wg1 listen-port 9999
n0 wg set wg1 peer "$pub2" endpoint 127.0.0.1:20000
n1 ping6 -W 1 -c 1 fd00::2
[[ $(n2 wg show wg2 endpoints) == "$pub1	127.212.121.99:9999" ]]

# Test using IPv6 that roaming works
n1 wg set wg1 listen-port 9998
n1 wg set wg1 peer "$pub2" endpoint [::1]:20000
n1 ping -W 1 -c 1 192.168.241.2
[[ $(n2 wg show wg2 endpoints) == "$pub1	[::1]:9998" ]]

# Test that crypto-RP filter works
n1 wg set wg1 peer "$pub2" allowed-ips 192.168.241.0/24
exec 4< <(n1 ncat -l -u -p 1111)
nmap_pid=$!
waitncatudp $netns1
n2 ncat -u 192.168.241.1 1111 <<<"X"
read -r -N 1 -t 1 out <&4 && [[ $out == "X" ]]
kill $nmap_pid
more_specific_key="$(pp wg genkey | pp wg pubkey)"
n0 wg set wg1 peer "$more_specific_key" allowed-ips 192.168.241.2/32
n0 wg set wg2 listen-port 9997
exec 4< <(n1 ncat -l -u -p 1111)
nmap_pid=$!
waitncatudp $netns1
n2 ncat -u 192.168.241.1 1111 <<<"X"
! read -r -N 1 -t 1 out <&4
kill $nmap_pid
n0 wg set wg1 peer "$more_specific_key" remove
[[ $(n1 wg show wg1 endpoints) == "$pub2	[::1]:9997" ]]

ip1 link del wg1
ip2 link del wg2

# Test using NAT. We now change the topology to this:
# ┌────────────────────────────────────────┐    ┌────────────────────────────────────────────────┐     ┌────────────────────────────────────────┐
# │             $ns1 namespace             │    │                 $ns0 namespace                 │     │             $ns2 namespace             │
# │                                        │    │                                                │     │                                        │
# │  ┌─────┐             ┌─────┐           │    │    ┌──────┐              ┌──────┐              │     │  ┌─────┐            ┌─────┐            │
# │  │ wg1 │─────────────│vethc│───────────┼────┼────│vethrc│              │vethrs│──────────────┼─────┼──│veths│────────────│ wg2 │            │
# │  ├─────┴──────────┐  ├─────┴──────────┐│    │    ├──────┴─────────┐    ├──────┴────────────┐ │     │  ├─────┴──────────┐ ├─────┴──────────┐ │
# │  │192.168.241.1/24│  │192.168.1.100/24││    │    │192.168.1.100/24│    │10.0.0.1/24        │ │     │  │10.0.0.100/24   │ │192.168.241.2/24│ │
# │  │fd00::1/24      │  │                ││    │    │                │    │SNAT:192.168.1.0/24│ │     │  │                │ │fd00::2/24      │ │
# │  └────────────────┘  └────────────────┘│    │    └────────────────┘    └───────────────────┘ │     │  └────────────────┘ └────────────────┘ │
# └────────────────────────────────────────┘    └────────────────────────────────────────────────┘     └────────────────────────────────────────┘

# ip1 link add dev wg1 type wireguard
# ip2 link add dev wg1 type wireguard

n1 $program wg1
n2 $program wg2

configure_peers

ip0 link add vethrc type veth peer name vethc
ip0 link add vethrs type veth peer name veths
ip0 link set vethc netns $netns1
ip0 link set veths netns $netns2
ip0 link set vethrc up
ip0 link set vethrs up
ip0 addr add 192.168.1.1/24 dev vethrc
ip0 addr add 10.0.0.1/24 dev vethrs
ip1 addr add 192.168.1.100/24 dev vethc
ip1 link set vethc up
ip1 route add default via 192.168.1.1
ip2 addr add 10.0.0.100/24 dev veths
ip2 link set veths up
waitiface $netns0 vethrc
waitiface $netns0 vethrs
waitiface $netns1 vethc
waitiface $netns2 veths

n0 bash -c 'printf 1 > /proc/sys/net/ipv4/ip_forward'
n0 bash -c 'printf 2 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout'
n0 bash -c 'printf 2 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream'
n0 iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -d 10.0.0.0/24 -j SNAT --to 10.0.0.1

n0 wg set wg1 peer "$pub2" endpoint 10.0.0.100:20000 persistent-keepalive 1
n1 ping -W 1 -c 1 192.168.241.2
n2 ping -W 1 -c 1 192.168.241.1
[[ $(n2 wg show wg2 endpoints) == "$pub1	10.0.0.1:10000" ]]
# Demonstrate n2 can still send packets to n1, since persistent-keepalive will prevent connection tracking entry from expiring (to see entries: `n0 conntrack -L`).
pp sleep 3
n2 ping -W 1 -c 1 192.168.241.1

n0 iptables -t nat -F
ip0 link del vethrc
ip0 link del vethrs
ip1 link del wg1
ip2 link del wg2

# Test that saddr routing is sticky but not too sticky, changing to this topology:
# ┌────────────────────────────────────────┐    ┌────────────────────────────────────────┐
# │             $ns1 namespace             │    │             $ns2 namespace             │
# │                                        │    │                                        │
# │  ┌─────┐             ┌─────┐           │    │  ┌─────┐            ┌─────┐            │
# │  │ wg1 │─────────────│veth1│───────────┼────┼──│veth2│────────────│ wg2 │            │
# │  ├─────┴──────────┐  ├─────┴──────────┐│    │  ├─────┴──────────┐ ├─────┴──────────┐ │
# │  │192.168.241.1/24│  │10.0.0.1/24     ││    │  │10.0.0.2/24     │ │192.168.241.2/24│ │
# │  │fd00::1/24      │  │fd00:aa::1/96   ││    │  │fd00:aa::2/96   │ │fd00::2/24      │ │
# │  └────────────────┘  └────────────────┘│    │  └────────────────┘ └────────────────┘ │
# └────────────────────────────────────────┘    └────────────────────────────────────────┘

# ip1 link add dev wg1 type wireguard
# ip2 link add dev wg1 type wireguard
n1 $program wg1
n2 $program wg2

configure_peers

ip1 link add veth1 type veth peer name veth2
ip1 link set veth2 netns $netns2
n1 bash -c 'printf 0 > /proc/sys/net/ipv6/conf/veth1/accept_dad'
n2 bash -c 'printf 0 > /proc/sys/net/ipv6/conf/veth2/accept_dad'
n1 bash -c 'printf 1 > /proc/sys/net/ipv4/conf/veth1/promote_secondaries'

# First we check that we aren't overly sticky and can fall over to new IPs when old ones are removed
ip1 addr add 10.0.0.1/24 dev veth1
ip1 addr add fd00:aa::1/96 dev veth1
ip2 addr add 10.0.0.2/24 dev veth2
ip2 addr add fd00:aa::2/96 dev veth2
ip1 link set veth1 up
ip2 link set veth2 up
waitiface $netns1 veth1
waitiface $netns2 veth2
n0 wg set wg1 peer "$pub2" endpoint 10.0.0.2:20000
n1 ping -W 1 -c 1 192.168.241.2
ip1 addr add 10.0.0.10/24 dev veth1
ip1 addr del 10.0.0.1/24 dev veth1
n1 ping -W 1 -c 1 192.168.241.2
n0 wg set wg1 peer "$pub2" endpoint [fd00:aa::2]:20000
n1 ping -W 1 -c 1 192.168.241.2
ip1 addr add fd00:aa::10/96 dev veth1
ip1 addr del fd00:aa::1/96 dev veth1
n1 ping -W 1 -c 1 192.168.241.2

# Now we show that we can successfully do reply to sender routing
ip1 link set veth1 down
ip2 link set veth2 down
ip1 addr flush dev veth1
ip2 addr flush dev veth2
ip1 addr add 10.0.0.1/24 dev veth1
ip1 addr add 10.0.0.2/24 dev veth1
ip1 addr add fd00:aa::1/96 dev veth1
ip1 addr add fd00:aa::2/96 dev veth1
ip2 addr add 10.0.0.3/24 dev veth2
ip2 addr add fd00:aa::3/96 dev veth2
ip1 link set veth1 up
ip2 link set veth2 up
waitiface $netns1 veth1
waitiface $netns2 veth2
n0 wg set wg2 peer "$pub1" endpoint 10.0.0.1:10000
n2 ping -W 1 -c 1 192.168.241.1
[[ $(n0 wg show wg2 endpoints) == "$pub1	10.0.0.1:10000" ]]
n0 wg set wg2 peer "$pub1" endpoint [fd00:aa::1]:10000
n2 ping -W 1 -c 1 192.168.241.1
[[ $(n0 wg show wg2 endpoints) == "$pub1	[fd00:aa::1]:10000" ]]
n0 wg set wg2 peer "$pub1" endpoint 10.0.0.2:10000
n2 ping -W 1 -c 1 192.168.241.1
[[ $(n0 wg show wg2 endpoints) == "$pub1	10.0.0.2:10000" ]]
n0 wg set wg2 peer "$pub1" endpoint [fd00:aa::2]:10000
n2 ping -W 1 -c 1 192.168.241.1
[[ $(n0 wg show wg2 endpoints) == "$pub1	[fd00:aa::2]:10000" ]]

ip1 link del veth1
ip1 link del wg1
ip2 link del wg2

# Test that Netlink/IPC is working properly by doing things that usually cause split responses

n0 $program wg0
sleep 5
config=( "[Interface]" "PrivateKey=$(wg genkey)" "[Peer]" "PublicKey=$(wg genkey)" )
for a in {1..255}; do
    for b in {0..255}; do
        config+=( "AllowedIPs=$a.$b.0.0/16,$a::$b/128" )
    done
done
n0 wg setconf wg0 <(printf '%s\n' "${config[@]}")
i=0
for ip in $(n0 wg show wg0 allowed-ips); do
    ((++i))
done
((i == 255*256*2+1))
ip0 link del wg0

n0 $program wg0
config=( "[Interface]" "PrivateKey=$(wg genkey)" )
for a in {1..40}; do
    config+=( "[Peer]" "PublicKey=$(wg genkey)" )
    for b in {1..52}; do
        config+=( "AllowedIPs=$a.$b.0.0/16" )
    done
done
n0 wg setconf wg0 <(printf '%s\n' "${config[@]}")
i=0
while read -r line; do
    j=0
    for ip in $line; do
        ((++j))
    done
    ((j == 53))
    ((++i))
done < <(n0 wg show wg0 allowed-ips)
((i == 40))
ip0 link del wg0

n0 $program wg0
config=( )
for i in {1..29}; do
    config+=( "[Peer]" "PublicKey=$(wg genkey)" )
done
config+=( "[Peer]" "PublicKey=$(wg genkey)" "AllowedIPs=255.2.3.4/32,abcd::255/128" )
n0 wg setconf wg0 <(printf '%s\n' "${config[@]}")
n0 wg showconf wg0 > /dev/null
ip0 link del wg0

! n0 wg show doesnotexist || false

declare -A objects
while read -t 0.1 -r line 2>/dev/null || [[ $? -ne 142 ]]; do
    [[ $line =~ .*(wg[0-9]+:\ [A-Z][a-z]+\ [0-9]+)\ .*(created|destroyed).* ]] || continue
    objects["${BASH_REMATCH[1]}"]+="${BASH_REMATCH[2]}"
done < /dev/kmsg
alldeleted=1
for object in "${!objects[@]}"; do
    if [[ ${objects["$object"]} != *createddestroyed ]]; then
        echo "Error: $object: merely ${objects["$object"]}" >&3
        alldeleted=0
    fi
done
[[ $alldeleted -eq 1 ]]
pretty "" "Objects that were created were also destroyed."
