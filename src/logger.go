package main

import (
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

func NewLogger() *Logger {
	logger := new(Logger)
	logger.Debug = log.New(os.Stdout,
		"DEBUG: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	logger.Info = log.New(os.Stdout,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	logger.Error = log.New(os.Stdout,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	return logger
}
