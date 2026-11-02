package logger

import "io"

// NewWithWriter logs to w without colours (neko: the embedded server logs to the caller).
func NewWithWriter(name, rawLevel string, w io.Writer) *Logger {
	appName := "[" + name + "]"
	return &Logger{
		name:           name,
		level:          parseLevel(rawLevel),
		consoleWriter:  w,
		appNameText:    appName,
		appNameColored: appName,
	}
}
