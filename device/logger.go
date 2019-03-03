/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

const (
	LogLevelSilent = iota
	LogLevelError
	LogLevelInfo
	LogLevelDebug
)

type Logger struct {
	Debug *log.Logger
	Info  *log.Logger
	Error *log.Logger
}

func NewLogger(level int, prepend string) *Logger {
	output := os.Stdout
	logger := new(Logger)

	logErr, logInfo, logDebug := func() (io.Writer, io.Writer, io.Writer) {
		if level >= LogLevelDebug {
			return output, output, output
		}
		if level >= LogLevelInfo {
			return output, output, ioutil.Discard
		}
		if level >= LogLevelError {
			return output, ioutil.Discard, ioutil.Discard
		}
		return ioutil.Discard, ioutil.Discard, ioutil.Discard
	}()

	logger.Debug = log.New(logDebug,
		"DEBUG: "+prepend,
		log.Ldate|log.Ltime,
	)

	logger.Info = log.New(logInfo,
		"INFO: "+prepend,
		log.Ldate|log.Ltime,
	)
	logger.Error = log.New(logErr,
		"ERROR: "+prepend,
		log.Ldate|log.Ltime,
	)
	return logger
}
