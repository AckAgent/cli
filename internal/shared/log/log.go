// Package log provides unified logging for the AckAgent CLI.
//
// Log levels can be configured via:
//   - Environment variable: ACKAGENT_LOG_LEVEL=debug|info|warn|error
//   - CLI flag: --log-level=debug|info|warn|error
//
// Default level is info.
package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	currentLevel = LevelInfo
	levelMu      sync.RWMutex
	output       io.Writer = os.Stderr
)

// SetLevel sets the global log level.
func SetLevel(level Level) {
	levelMu.Lock()
	currentLevel = level
	levelMu.Unlock()
}

// SetLevelFromString sets the log level from a string.
// Valid values: "debug", "info", "warn", "error" (case-insensitive).
// Invalid values default to info.
func SetLevelFromString(s string) {
	switch strings.ToLower(s) {
	case "debug":
		SetLevel(LevelDebug)
	case "info":
		SetLevel(LevelInfo)
	case "warn", "warning":
		SetLevel(LevelWarn)
	case "error":
		SetLevel(LevelError)
	default:
		SetLevel(LevelInfo)
	}
}

// GetLevel returns the current log level.
func GetLevel() Level {
	levelMu.RLock()
	defer levelMu.RUnlock()
	return currentLevel
}

// SetOutput sets the output writer for all loggers.
func SetOutput(w io.Writer) {
	levelMu.Lock()
	output = w
	levelMu.Unlock()
}

// levelName returns the display name for a level.
func levelName(l Level) string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// shouldLog returns true if the given level should be logged.
func shouldLog(level Level) bool {
	levelMu.RLock()
	defer levelMu.RUnlock()
	return level >= currentLevel
}

// log writes a log message if the level is enabled.
func log(level Level, component, format string, args ...any) {
	if !shouldLog(level) {
		return
	}

	levelMu.RLock()
	w := output
	levelMu.RUnlock()

	timestamp := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)

	var line string
	if component != "" {
		line = fmt.Sprintf("%s [%s] [%s] %s\n", timestamp, levelName(level), component, msg)
	} else {
		line = fmt.Sprintf("%s [%s] %s\n", timestamp, levelName(level), msg)
	}

	fmt.Fprint(w, line)
}

// Package-level logging functions (no component)

// Debug logs at debug level.
func Debug(format string, args ...any) {
	log(LevelDebug, "", format, args...)
}

// Info logs at info level.
func Info(format string, args ...any) {
	log(LevelInfo, "", format, args...)
}

// Warn logs at warn level.
func Warn(format string, args ...any) {
	log(LevelWarn, "", format, args...)
}

// Error logs at error level.
func Error(format string, args ...any) {
	log(LevelError, "", format, args...)
}

// Logger provides component-scoped logging.
type Logger struct {
	component string
}

// New creates a new logger with the given component name.
func New(component string) *Logger {
	return &Logger{component: component}
}

// Debug logs at debug level with the component prefix.
func (l *Logger) Debug(format string, args ...any) {
	log(LevelDebug, l.component, format, args...)
}

// Info logs at info level with the component prefix.
func (l *Logger) Info(format string, args ...any) {
	log(LevelInfo, l.component, format, args...)
}

// Warn logs at warn level with the component prefix.
func (l *Logger) Warn(format string, args ...any) {
	log(LevelWarn, l.component, format, args...)
}

// Error logs at error level with the component prefix.
func (l *Logger) Error(format string, args ...any) {
	log(LevelError, l.component, format, args...)
}

// IsDebug returns true if debug logging is enabled.
func IsDebug() bool {
	return shouldLog(LevelDebug)
}

// InitFromEnv initializes the log level from the ACKAGENT_LOG_LEVEL environment variable.
func InitFromEnv() {
	if level := os.Getenv("ACKAGENT_LOG_LEVEL"); level != "" {
		SetLevelFromString(level)
	}
}
