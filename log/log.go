package log

import (
	"log"
)

// public func
var (
	Errorf   func(format string, v ...interface{}) = log.Printf
	Infof    func(format string, v ...interface{}) = log.Printf
	Debugf   func(format string, v ...interface{}) = log.Printf
	Flush    func()                                = func() {}
	SetLevel func(level int)                       = func(level int) {}
)

const (
	LevelTrace = iota
	LevelDebug
	LevelInfo
	LevelNotice
	LevelWarn
	LevelError
	LevelFatal
)
