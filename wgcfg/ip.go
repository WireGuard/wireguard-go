package wgcfg

import (
	"fmt"
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

func (ip *IP) IP() net.IP { return net.IP(ip.Addr[:]) }
func (ip *IP) Is6() bool  { return !ip.Is4() }
func (ip *IP) Is4() bool {
	return ip.Addr[0] == 0 && ip.Addr[1] == 0 &&
		ip.Addr[2] == 0 && ip.Addr[3] == 0 &&
		ip.Addr[4] == 0 && ip.Addr[5] == 0 &&
		ip.Addr[6] == 0 && ip.Addr[7] == 0 &&
		ip.Addr[8] == 0 && ip.Addr[9] == 0 &&
		ip.Addr[10] == 0xff && ip.Addr[11] == 0xff
}
func (ip *IP) To4() []byte {
	if ip.Is4() {
		return ip.Addr[12:16]
	} else {
		return nil
	}
}
func (ip *IP) Equal(x *IP) bool {
	if ip == nil || x == nil {
		return false
	}
	// TODO: this isn't hard, write a more efficient implementation.
	return ip.IP().Equal(x.IP())
}

func (ip IP) MarshalText() ([]byte, error) {
	return []byte(ip.String()), nil
}

func (ip *IP) UnmarshalText(text []byte) error {
	parsedIP := ParseIP(string(text))
	if parsedIP == nil {
		return fmt.Errorf("wgcfg.IP: UnmarshalText: bad IP address %q", string(text))
	}
	*ip = *parsedIP
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
// If the string is not a valid IP address, ParseIP returns nil.
func ParseIP(s string) *IP {
	netIP := net.ParseIP(s)
	if netIP == nil {
		return nil
	}
	ip := new(IP)
	copy(ip.Addr[:], netIP.To16())
	return ip
}

// CIDR is a compact IP address and subnet mask.
type CIDR struct {
	IP   IP
	Mask uint8 // 0-32 for IsIPv4, 4-128 for IsIPv6
}

// ParseCIDR parses CIDR notation into a CIDR type.
// Typical CIDR strings look like "192.168.1.0/24".
func ParseCIDR(s string) (cidr *CIDR, err error) {
	netIP, netAddr, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	cidr = new(CIDR)
	copy(cidr.IP.Addr[:], netIP.To16())
	ones, _ := netAddr.Mask.Size()
	cidr.Mask = uint8(ones)

	return cidr, nil
}

func (r CIDR) String() string { return r.IPNet().String() }

func (r *CIDR) IPNet() *net.IPNet {
	bits := 128
	if r.IP.Is4() {
		bits = 32
	}
	return &net.IPNet{IP: r.IP.IP(), Mask: net.CIDRMask(int(r.Mask), bits)}
}
func (r *CIDR) Contains(ip *IP) bool {
	if r == nil || ip == nil {
		return false
	}
	// TODO: this isn't hard, write a more efficient implementation.
	return r.IPNet().Contains(ip.IP())
}

func (r CIDR) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r *CIDR) UnmarshalText(text []byte) error {
	cidr, err := ParseCIDR(string(text))
	if err != nil {
		return fmt.Errorf("wgcfg.CIDR: UnmarshalText: %v", err)
	}
	*r = *cidr
	return nil
}
