package flags

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"golang.zx2c4.com/wireguard/device"
)

func Parse(opts *Options) error {
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <interface-name>\n", os.Args[0])
		pflag.PrintDefaults()
	}

	pflag.IntVar(&opts.MTU, "mtu", device.DefaultMTU, "Set the MTU of the device")
	pflag.BoolVar(&opts.Foreground, "foreground", false, "Remain in the foreground")
	pflag.BoolVarP(&opts.ShowVersion, "version", "v", false, "Print the version number and exit")

	pflag.Parse()

	if opts.ShowVersion {
		return nil
	}

	if err := setInterfaceName(opts); err != nil {
		return err
	}
	return nil
}

func setInterfaceName(opts *Options) error {
	if pflag.NArg() != 1 {
		return fmt.Errorf("Must pass exactly one interface name, but got %d", pflag.NArg())
	}
	opts.InterfaceName = pflag.Arg(0)
	return nil
}
