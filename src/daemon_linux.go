package main

import (
	"os"
)

/* Daemonizes the process on linux
 *
 * This is done by spawning and releasing a copy with the --foreground flag
 *
 * TODO: Use env variable to spawn in background
 */

func Daemonize(attr *os.ProcAttr) error {
	argv := []string{os.Args[0], "--foreground"}
	argv = append(argv, os.Args[1:]...)
	process, err := os.StartProcess(
		argv[0],
		argv,
		attr,
	)
	if err != nil {
		return err
	}
	process.Release()
	return nil
}
