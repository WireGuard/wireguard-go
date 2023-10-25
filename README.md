# Go Implementation of AmneziaWG

AmneziaWG is a contemporary version of the WireGuard protocol. It's a fork of WireGuard-Go and offers protection against detection by Deep Packet Inspection (DPI) systems. At the same time, it retains the simplified architecture and high performance of the original.

The precursor, WireGuard, is known for its efficiency but had issues with detection due to its distinctive packet signatures.
AmneziaWG addresses this problem by employing advanced obfuscation methods, allowing its traffic to blend seamlessly with regular internet traffic.
As a result, AmneziaWG maintains high performance while adding an extra layer of stealth, making it a superb choice for those seeking a fast and discreet VPN connection.

## Usage

Simply run:

```
$ amnezia-wg wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run amnezia-wg without forking to the background, pass `-f` or `--foreground`:

```
$ amnezia-wg -f wg0
```
When an interface is running, you may use [`amnezia-wg-tools `](https://github.com/amnezia-vpn/amnezia-wg-tools) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; you should run amnezia-wg instead of using default linux kernel module.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.
This runs on MacOS, you should use it from [awg-apple](https://github.com/amnezia-vpn/awg-apple)

### Windows

This runs on Windows, you should use it from [awg-windows](https://github.com/amnezia-vpn/awg-windows), which uses this as a module.


## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://github.com/amnezia-vpn/amnezia-wg
$ cd amnezia-wg
$ make
```
