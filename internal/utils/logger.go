// Package utils provides utility functions and types for the Tracium agents
package utils

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/crewjam/rfc5424"
)

// Logger defines the interface for logging operations
type Logger interface {
	LogInfo(message string, meta map[string]string)
	LogWarn(message string, meta map[string]string)
	LogError(message string, meta map[string]string)
	LogDebug(message string, meta map[string]string)
}

// RFC5424Logger implements Logger with RFC 5424 compliant syslog format using crewjam/rfc5424
type RFC5424Logger struct {
	appName   string
	hostname  string
	processID string
	facility  rfc5424.Priority // Using the library's priority type for facility
}

// NewRFC5424Logger creates a new RFC 5424 compliant logger using the crewjam/rfc5424 library
func NewRFC5424Logger(appName string) (*RFC5424Logger, error) {
	// Get hostname dynamically
	hostname, err := getHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Get process ID
	processID := strconv.Itoa(os.Getpid())

	return &RFC5424Logger{
		appName:   appName,
		hostname:  hostname,
		processID: processID,
		facility:  rfc5424.User, // User-level facility
	}, nil
}

// getHostname retrieves the system hostname dynamically
func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost", nil // Fallback
	}
	return hostname, nil
}

// createMessage creates an RFC 5424 message using the library
func (l *RFC5424Logger) createMessage(severity rfc5424.Priority, message string, meta map[string]string) *rfc5424.Message {
	msg := &rfc5424.Message{
		Priority:  l.facility | severity, // Combine facility and severity
		Timestamp: time.Now().UTC(),
		Hostname:  l.hostname,
		AppName:   l.appName,
		ProcessID: l.processID,
		MessageID: fmt.Sprintf("ID%d", time.Now().UnixNano()%100000),
		Message:   []byte(message),
	}

	// Add structured data if metadata is provided
	if len(meta) > 0 {
		for key, value := range meta {
			msg.AddDatum("meta@1", key, value)
		}
	}

	return msg
}

// writeLog writes the formatted RFC 5424 log entry to stdout
func (l *RFC5424Logger) writeLog(severity rfc5424.Priority, message string, meta map[string]string) {
	msg := l.createMessage(severity, message, meta)
	_, err := msg.WriteTo(os.Stdout)
	if err != nil {
		// Fallback to simple format if writing fails
		fmt.Printf("<%d>1 %s %s %s %s - - %s\n",
			int(l.facility|severity),
			time.Now().UTC().Format(time.RFC3339),
			l.hostname, l.appName, l.processID, message)
		return
	}
	fmt.Println() // Add newline after the message
}

// LogInfo logs an informational message (severity Info)
func (l *RFC5424Logger) LogInfo(message string, meta map[string]string) {
	l.writeLog(rfc5424.Info, message, meta)
}

// LogWarn logs a warning message (severity Warning)
func (l *RFC5424Logger) LogWarn(message string, meta map[string]string) {
	l.writeLog(rfc5424.Warning, message, meta)
}

// LogError logs an error message (severity Error)
func (l *RFC5424Logger) LogError(message string, meta map[string]string) {
	l.writeLog(rfc5424.Error, message, meta)
}

// LogDebug logs a debug message (severity Debug)
func (l *RFC5424Logger) LogDebug(message string, meta map[string]string) {
	l.writeLog(rfc5424.Debug, message, meta)
}

// DefaultLogger is the global logger instance
var DefaultLogger *RFC5424Logger

// InitDefaultLogger initializes the global logger instance
func InitDefaultLogger() error {
	logger, err := NewRFC5424Logger("Tracium")
	if err != nil {
		return err
	}
	DefaultLogger = logger
	return nil
}

// Convenience functions using the global logger

// LogInfo logs an informational message using the default logger
func LogInfo(message string, meta map[string]string) {
	if DefaultLogger != nil {
		DefaultLogger.LogInfo(message, meta)
	}
}

// LogWarn logs a warning message using the default logger
func LogWarn(message string, meta map[string]string) {
	if DefaultLogger != nil {
		DefaultLogger.LogWarn(message, meta)
	}
}

// LogError logs an error message using the default logger
func LogError(message string, meta map[string]string) {
	if DefaultLogger != nil {
		DefaultLogger.LogError(message, meta)
	}
}

// LogDebug logs a debug message using the default logger
func LogDebug(message string, meta map[string]string) {
	if DefaultLogger != nil {
		DefaultLogger.LogDebug(message, meta)
	}
}
