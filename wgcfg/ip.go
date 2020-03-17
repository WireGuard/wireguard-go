package wgcfg

import (
	"fmt"
	"math"
	"net"
)

// IP is an IPv4 or an IPv6 address.
//
// Internally the address is always represented in its IPv6 form.
// IPv4 addresses use the IPv4-in-IPv6 syntax.
type IP struct {
	Addr [16]byte
}

func (ip IP) String() string { return net.IP(ip.Addr[:]).String() }

// IP converts ip into a standard library net.IP.
func (ip IP) IP() net.IP { return net.IP(ip.Addr[:]) }

// Is6 reports whether ip is an IPv6 address.
func (ip IP) Is6() bool { return !ip.Is4() }

// Is4 reports whether ip is an IPv4 address.
func (ip IP) Is4() bool {
	return ip.Addr[0] == 0 && ip.Addr[1] == 0 &&
		ip.Addr[2] == 0 && ip.Addr[3] == 0 &&
		ip.Addr[4] == 0 && ip.Addr[5] == 0 &&
		ip.Addr[6] == 0 && ip.Addr[7] == 0 &&
		ip.Addr[8] == 0 && ip.Addr[9] == 0 &&
		ip.Addr[10] == 0xff && ip.Addr[11] == 0xff
}

// To4 returns either a 4 byte slice for an IPv4 address, or nil if
// it's not IPv4.
func (ip IP) To4() []byte {
	if ip.Is4() {
		return ip.Addr[12:16]
	} else {
		return nil
	}
}

// Equal reports whether ip == x.
func (ip IP) Equal(x IP) bool {
	return ip == x
}

func (ip IP) MarshalText() ([]byte, error) {
	return []byte(ip.String()), nil
}

func (ip *IP) UnmarshalText(text []byte) error {
	parsedIP, ok := ParseIP(string(text))
	if !ok {
		return fmt.Errorf("wgcfg.IP: UnmarshalText: bad IP address %q", text)
	}
	*ip = parsedIP
	return nil
}

func IPv4(b0, b1, b2, b3 byte) (ip IP) {
	ip.Addr[10], ip.Addr[11] = 0xff, 0xff // IPv4-in-IPv6 prefix
	ip.Addr[12] = b0
	ip.Addr[13] = b1
	ip.Addr[14] = b2
	ip.Addr[15] = b3
	return ip
}

// ParseIP parses the string representation of an address into an IP.
//
// It accepts IPv4 notation such as "1.2.3.4" and IPv6 notation like ""::0".
// The ok result reports whether s was a valid IP and ip is valid.
func ParseIP(s string) (ip IP, ok bool) {
	netIP := net.ParseIP(s)
	if netIP == nil {
		return IP{}, false
	}
	copy(ip.Addr[:], netIP.To16())
	return ip, true
}

// CIDR is a compact IP address and subnet mask.
type CIDR struct {
	IP   IP
	Mask uint8 // 0-32 for IsIPv4, 4-128 for IsIPv6
}

// ParseCIDR parses CIDR notation into a CIDR type.
// Typical CIDR strings look like "192.168.1.0/24".
func ParseCIDR(s string) (CIDR, error) {
	netIP, netAddr, err := net.ParseCIDR(s)
	if err != nil {
		return CIDR{}, err
	}
	var cidr CIDR
	copy(cidr.IP.Addr[:], netIP.To16())
	ones, _ := netAddr.Mask.Size()
	cidr.Mask = uint8(ones)

	return cidr, nil
}

func (r CIDR) String() string { return r.IPNet().String() }

func (r CIDR) IPNet() *net.IPNet {
	bits := 128
	if r.IP.Is4() {
		bits = 32
	}
	return &net.IPNet{IP: r.IP.IP(), Mask: net.CIDRMask(int(r.Mask), bits)}
}

func (r CIDR) Contains(ip IP) bool {
	c := int8(r.Mask)
	i := 0
	if r.IP.Is4() {
		i = 12
		if ip.Is6() {
			return false
		}
	}
	for ; i < 16 && c > 0; i++ {
		var x uint8
		if c < 8 {
			x = 8 - uint8(c)
		}
		m := uint8(math.MaxUint8) >> x << x
		a := r.IP.Addr[i] & m
		b := ip.Addr[i] & m
		if a != b {
			return false
		}
		c -= 8
	}
	return true
}

func (r CIDR) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r *CIDR) UnmarshalText(text []byte) error {
	cidr, err := ParseCIDR(string(text))
	if err != nil {
		return fmt.Errorf("wgcfg.CIDR: UnmarshalText: %v", err)
	}
	*r = cidr
	return nil
}
