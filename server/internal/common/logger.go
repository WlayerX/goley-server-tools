package common

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Logger is a minimal structured logger with file + stdout output.
type Logger struct {
	component string
	file      *os.File
}

func NewLogger(component string) *Logger {
	logDir := "logs"
	_ = os.MkdirAll(logDir, 0755)
	path := filepath.Join(logDir, component+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log file: %v", err)
	}
	return &Logger{component: component, file: f}
}

func (l *Logger) Logf(format string, args ...interface{}) {
	msg := fmt.Sprintf("%s  [%s]  %s",
		time.Now().Format("15:04:05.000"),
		l.component,
		fmt.Sprintf(format, args...))
	fmt.Println(msg)
	if l.file != nil {
		fmt.Fprintln(l.file, msg)
	}
}

func (l *Logger) Close() {
	if l.file != nil {
		_ = l.file.Close()
	}
}
