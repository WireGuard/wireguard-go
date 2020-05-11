/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
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

var _ Logger = &basicLogger{}

type Logger interface {
	Debug(v ...interface{})
	Debugf(f string, v ...interface{})
	Info(v ...interface{})
	Infof(f string, v ...interface{})
	Error(v ...interface{})
	Errorf(f string, v ...interface{})
}

type basicLogger struct {
	debug *log.Logger
	info  *log.Logger
	err   *log.Logger
}

func NewLogger(level int, prepend string) *basicLogger {
	output := os.Stdout

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

	return &basicLogger{
		debug: log.New(logDebug,
			"DEBUG: "+prepend,
			log.Ldate|log.Ltime,
		),
		info: log.New(logInfo,
			"INFO: "+prepend,
			log.Ldate|log.Ltime,
		),
		err: log.New(logErr,
			"ERROR: "+prepend,
			log.Ldate|log.Ltime,
		),
	}
}

func (l *basicLogger) Debug(v ...interface{}) {
	l.debug.Println(v...)
}

func (l *basicLogger) Debugf(f string, v ...interface{}) {
	l.debug.Printf(f, v...)
}

func (l *basicLogger) Info(v ...interface{}) {
	l.info.Println(v...)
}

func (l *basicLogger) Infof(f string, v ...interface{}) {
	l.info.Printf(f, v...)
}

func (l *basicLogger) Error(v ...interface{}) {
	l.err.Println(v...)
}

func (l *basicLogger) Errorf(f string, v ...interface{}) {
	l.err.Printf(f, v...)
}
