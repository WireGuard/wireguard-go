package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

const (
	LogLevelError = iota
	LogLevelInfo
	LogLevelDebug
)

type Logger struct {
	Debug *log.Logger
	Info  *log.Logger
	Error *log.Logger
}

func NewLogger(level int) *Logger {
	output := os.Stdout
	logger := new(Logger)

	logErr, logInfo, logDebug := func() (io.Writer, io.Writer, io.Writer) {
		if level >= LogLevelDebug {
			return output, output, output
		}
		if level >= LogLevelInfo {
			return output, output, ioutil.Discard
		}
		return output, ioutil.Discard, ioutil.Discard
	}()

	logger.Debug = log.New(logDebug,
		"DEBUG: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)

	logger.Info = log.New(logInfo,
		"INFO: ",
		log.Ldate|log.Ltime,
	)
	logger.Error = log.New(logErr,
		"ERROR: ",
		log.Ldate|log.Ltime,
	)
	return logger
}
