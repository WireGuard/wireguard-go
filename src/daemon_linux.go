package main

import (
	"os"
	"os/exec"
)

/* Daemonizes the process on linux
 *
 * This is done by spawning and releasing a copy with the --foreground flag
 */
func Daemonize(attr *os.ProcAttr) error {
	// I would like to use os.Executable,
	// however this means dropping support for Go <1.8
	path, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}

	argv := []string{os.Args[0], "--foreground"}
	argv = append(argv, os.Args[1:]...)
	process, err := os.StartProcess(
		path,
		argv,
		attr,
	)
	if err != nil {
		return err
	}
	process.Release()
	return nil
}
