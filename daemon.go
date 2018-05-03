package main

import (
	"os"
)

func Daemonize(attr *os.ProcAttr) error {
	path, err := os.Executable()
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
