# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go.

***WARNING:*** This is a work in progress and not ready for prime time, with no official "releases" yet. It is extremely rough around the edges and leaves much to be desired. There are bugs and we are not yet in a position to make claims about its security. Beware.

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however **YOU SHOULD NOT RUN THIS ON LINUX**. Instead use the kernel module; see the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

It is currently a work in progress to strip out the beginnings of an experiment done with the OpenVPN tuntap driver and instead port to the new UWP APIs for tunnels. In other words, this does not *yet* work on Windows.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of [go](https://golang.org) ≥ 1.11.

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## License

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    ---------------------------------------------------------------------------
    Additional Permissions For Submission to Apple App Store: Provided that you
    are otherwise in compliance with the GPLv2 for each covered work you convey
    (including without limitation making the Corresponding Source available in
    compliance with Section 3 of the GPLv2), you are granted the additional
    permission to convey through the Apple App Store non-source executable
    versions of the Program as incorporated into each applicable covered work
    as Executable Versions only under the Mozilla Public License version 2.0
    (https://www.mozilla.org/en-US/MPL/2.0/).
    

