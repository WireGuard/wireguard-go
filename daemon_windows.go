package main

import (
	"os"
)

/* Daemonizes the process on windows
 *
 * This is done by spawning and releasing a copy with the --foreground flag
 */

func Daemonize() error {
	argv := []string{os.Args[0], "--foreground"}
	argv = append(argv, os.Args[1:]...)
	attr := &os.ProcAttr{
		Dir: ".",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil,
			nil,
		},
	}
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
