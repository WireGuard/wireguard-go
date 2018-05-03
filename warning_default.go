// +build !linux

package main

import (
	"fmt"
	"os"
)

func Warning() {
	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "W   This is alpha software. It will very likely not   G")
	fmt.Fprintln(os.Stderr, "W   do what it is supposed to do, and things may go   G")
	fmt.Fprintln(os.Stderr, "W   horribly wrong. You have been warned. Proceed     G")
	fmt.Fprintln(os.Stderr, "W   at your own risk.                                 G")
	fmt.Fprintln(os.Stderr, "W                                                     G")
	fmt.Fprintln(os.Stderr, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING")
}
