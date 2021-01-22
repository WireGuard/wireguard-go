/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"log"
	"os"
)

// A Logger provides logging for a Device.
// The functions are Printf-style functions.
// They must be safe for concurrent use.
// They do not require a trailing newline in the format.
// If nil, that level of logging will be silent.
type Logger struct {
	Debugf func(format string, args ...interface{})
	Infof  func(format string, args ...interface{})
	Errorf func(format string, args ...interface{})
}

// Log levels for use with NewLogger.
const (
	LogLevelSilent = iota
	LogLevelError
	LogLevelInfo
	LogLevelDebug
)

// NewLogger constructs a Logger that writes to stdout.
// It logs at the specified log level and above.
// It decorates log lines with the log level, date, time, and prepend.
func NewLogger(level int, prepend string) *Logger {
	logger := new(Logger)
	logf := func(prefix string) func(string, ...interface{}) {
		return log.New(os.Stdout, prefix+": "+prepend, log.Ldate|log.Ltime).Printf
	}
	if level >= LogLevelDebug {
		logger.Debugf = logf("DEBUG")
	}
	if level >= LogLevelInfo {
		logger.Infof = logf("INFO")
	}
	if level >= LogLevelError {
		logger.Errorf = logf("ERROR")
	}
	return logger
}

func (device *Device) debugf(format string, args ...interface{}) {
	if device.log.Debugf != nil {
		device.log.Debugf(format, args...)
	}
}

func (device *Device) infof(format string, args ...interface{}) {
	if device.log.Infof != nil {
		device.log.Infof(format, args...)
	}
}

func (device *Device) errorf(format string, args ...interface{}) {
	if device.log.Errorf != nil {
		device.log.Errorf(format, args...)
	}
}
