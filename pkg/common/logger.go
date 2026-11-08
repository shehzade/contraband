package common

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelSuccess
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelSuccess:
		return "SUCCESS"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

type LogMode int

const (
	LogModeTerminal LogMode = iota
	LogModeJSON
)

// ANSI Color Codes
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiRed     = "\033[1;31m"
	ansiGreen   = "\033[1;32m"
	ansiYellow  = "\033[1;33m"
	ansiCyan    = "\033[1;36m"
	ansiMagenta = "\033[1;35m"
	ansiDim     = "\033[2m"
)

// Logger is the core logging interface for Contraband
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...any)
	Info(msg string)
	Infof(format string, args ...any)
	Success(msg string)
	Successf(format string, args ...any)
	Warn(msg string)
	Warnf(format string, args ...any)
	Error(msg string)
	Errorf(format string, args ...any)
	Fatal(msg string)
	Fatalf(format string, args ...any)
	WithField(key string, val any) Logger
	WithFields(fields map[string]any) Logger
	SetLevel(level LogLevel)
	SetMode(mode LogMode)
	SetOutput(w io.Writer)
	SetNoColor(noColor bool)
}

// JSONLogEntry represents a serialized JSON log line
type JSONLogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Indicator string         `json:"indicator"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type appLogger struct {
	mu      sync.Mutex
	out     io.Writer
	level   LogLevel
	mode    LogMode
	noColor bool
	fields  map[string]any
	// exitFunc allows mocking os.Exit in tests if needed
	exitFunc func(code int)
}

// NewLogger creates a new configured Logger instance
func NewLogger(out io.Writer, level LogLevel, mode LogMode) Logger {
	if out == nil {
		out = os.Stdout
	}
	noColor := os.Getenv("NO_COLOR") != ""
	return &appLogger{
		out:      out,
		level:    level,
		mode:     mode,
		noColor:  noColor,
		fields:   make(map[string]any),
		exitFunc: os.Exit,
	}
}

var (
	defaultLoggerMu sync.RWMutex
	defaultLogger   = NewLogger(os.Stdout, LogLevelInfo, LogModeTerminal)
)

// Global helper accessors
func GetLogger() Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger
}
func SetGlobalLogger(l Logger)            { defaultLoggerMu.Lock(); defaultLogger = l; defaultLoggerMu.Unlock() }
func Debugf(format string, args ...any)   { defaultLogger.Debugf(format, args...) }
func Infof(format string, args ...any)    { defaultLogger.Infof(format, args...) }
func Successf(format string, args ...any) { defaultLogger.Successf(format, args...) }
func Warnf(format string, args ...any)    { defaultLogger.Warnf(format, args...) }
func Errorf(format string, args ...any)   { defaultLogger.Errorf(format, args...) }
func Fatalf(format string, args ...any)   { defaultLogger.Fatalf(format, args...) }

func (l *appLogger) SetLevel(level LogLevel) { l.mu.Lock(); l.level = level; l.mu.Unlock() }
func (l *appLogger) SetMode(mode LogMode)    { l.mu.Lock(); l.mode = mode; l.mu.Unlock() }
func (l *appLogger) SetOutput(w io.Writer)   { l.mu.Lock(); l.out = w; l.mu.Unlock() }
func (l *appLogger) SetNoColor(noColor bool) { l.mu.Lock(); l.noColor = noColor; l.mu.Unlock() }

func (l *appLogger) WithField(key string, val any) Logger {
	return l.WithFields(map[string]any{key: val})
}

func (l *appLogger) WithFields(fields map[string]any) Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	newFields := make(map[string]any, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &appLogger{
		out:      l.out,
		level:    l.level,
		mode:     l.mode,
		noColor:  l.noColor,
		fields:   newFields,
		exitFunc: l.exitFunc,
	}
}

func (l *appLogger) log(level LogLevel, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	now := time.Now().UTC()

	var indicator, colorCode string
	switch level {
	case LogLevelDebug:
		indicator = "[?]"
		colorCode = ansiMagenta
	case LogLevelInfo:
		indicator = "[*]"
		colorCode = ansiCyan
	case LogLevelSuccess:
		indicator = "[+]"
		colorCode = ansiGreen
	case LogLevelWarn:
		indicator = "[!]"
		colorCode = ansiYellow
	case LogLevelError:
		indicator = "[-]"
		colorCode = ansiRed
	case LogLevelFatal:
		indicator = "[-]"
		colorCode = ansiRed
	default:
		indicator = "[*]"
		colorCode = ansiCyan
	}

	if l.mode == LogModeJSON {
		entry := JSONLogEntry{
			Timestamp: now,
			Level:     level.String(),
			Indicator: indicator,
			Message:   msg,
			Fields:    l.fields,
		}
		data, _ := json.Marshal(entry)
		fmt.Fprintln(l.out, string(data))
	} else {
		prefix := indicator
		if !l.noColor {
			prefix = fmt.Sprintf("%s%s%s", colorCode, indicator, ansiReset)
		}
		timeStr := now.Format("15:04:05")
		if !l.noColor {
			timeStr = fmt.Sprintf("%s%s%s", ansiDim, timeStr, ansiReset)
		}
		fmt.Fprintf(l.out, "%s %s %s\n", timeStr, prefix, msg)
	}

	if level == LogLevelFatal && l.exitFunc != nil {
		l.exitFunc(1)
	}
}

func (l *appLogger) Debug(msg string)               { l.log(LogLevelDebug, msg) }
func (l *appLogger) Debugf(format string, a ...any) { l.log(LogLevelDebug, fmt.Sprintf(format, a...)) }
func (l *appLogger) Info(msg string)                { l.log(LogLevelInfo, msg) }
func (l *appLogger) Infof(format string, a ...any)  { l.log(LogLevelInfo, fmt.Sprintf(format, a...)) }
func (l *appLogger) Success(msg string)             { l.log(LogLevelSuccess, msg) }
func (l *appLogger) Successf(format string, a ...any) {
	l.log(LogLevelSuccess, fmt.Sprintf(format, a...))
}
func (l *appLogger) Warn(msg string)               { l.log(LogLevelWarn, msg) }
func (l *appLogger) Warnf(format string, a ...any) { l.log(LogLevelWarn, fmt.Sprintf(format, a...)) }
func (l *appLogger) Error(msg string)              { l.log(LogLevelError, msg) }
func (l *appLogger) Errorf(format string, a ...any) {
	l.log(LogLevelError, fmt.Sprintf(format, a...))
}
func (l *appLogger) Fatal(msg string) { l.log(LogLevelFatal, msg) }
func (l *appLogger) Fatalf(format string, a ...any) {
	l.log(LogLevelFatal, fmt.Sprintf(format, a...))
}
