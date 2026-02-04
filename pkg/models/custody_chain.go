// Package models - Custody Chain structures for digital evidence
package models

import (
	"time"
)

// CommandLogger is a function type for logging command executions with timing and metadata.
type CommandLogger func(id string, cmd string, args []string, startTime, endTime time.Time, exitCode int, err error, workingDirectory string, targetResource string)

const (
	// LogLevelInfo represents general informational messages
	LogLevelInfo = "INFO"

	// LogLevelWarning represents warning messages about potential issues
	LogLevelWarning = "WARNING"

	// LogLevelError represents error messages about failures
	LogLevelError = "ERROR"

	// LogLevelDebug represents detailed debugging information
	LogLevelDebug = "DEBUG"

	// LogLevelCritical represents critical errors that require immediate attention
	LogLevelCritical = "CRITICAL"
)

// CustodyChainEntry represents a complete digital evidence custody chain entry.
// This is the standardized structure used across all forensic agents (Evidex, Bitex, Tracium).
type CustodyChainEntry struct {
	// Unique identifier for this custody chain entry (UUID v4)
	ID string `json:"id"`

	// Agent/Source identification
	// Identifies which forensic agent created this entry (evidex, bitex, tracium)
	AgentType string `json:"agent_type"`

	// Version of the agent that created this entry (e.g., "1.0.0")
	AgentVersion string `json:"agent_version"`

	// Hostname of the machine where the agent ran
	AgentHostname string `json:"agent_hostname"`

	// Username who executed the agent
	AgentUser string `json:"agent_user"`

	// Timestamps
	// UTC timestamp when evidence collection started
	StartTimestamp time.Time `json:"start_timestamp"`

	// UTC timestamp when evidence collection completed
	EndTimestamp time.Time `json:"end_timestamp"`

	// Duration of the collection process
	Duration string `json:"duration"`

	// Timestamp when data was sent to Processor
	ProcessorSentAt time.Time `json:"processor_sent_at,omitempty"`

	// Hashes - Standardized cryptographic integrity verification
	// MD5 hash of the complete evidence package (for compatibility, not primary)
	MD5Hash string `json:"md5_hash"`

	// SHA1 hash of the complete evidence package (for legacy compatibility)
	SHA1Hash string `json:"sha1_hash"`

	// SHA256 hash of the complete evidence package (primary integrity check)
	SHA256Hash string `json:"sha256_hash"`

	// Metadata
	// Total size of evidence in bytes
	TotalSizeBytes int64 `json:"total_size_bytes"`

	// Total number of files/items collected
	ItemCount int `json:"item_count"`

	// Logs - RFC 5424 compliant syslog entries
	// Array of RFC 5424 formatted log entries from the agent
	LogEntries []LogEntry `json:"log_entries"`

	// Commands - All commands executed during collection
	// Complete history of all commands run by the agent
	CommandHistory []CommandExecution `json:"command_history"`
}

// CommandExecution represents a single command execution during evidence collection.
type CommandExecution struct {
	// Unique identifier for this command execution
	ID string `json:"id"`

	// The command that was executed (e.g., "fls", "exiftool", "ffprobe")
	Command string `json:"command"`

	// Full command-line arguments passed to the command
	Arguments []string `json:"arguments"`

	// UTC timestamp when command started
	StartTime time.Time `json:"start_time"`

	// UTC timestamp when command completed
	EndTime time.Time `json:"end_time"`

	// Duration of command execution
	Duration string `json:"duration"`

	// Exit code returned by the command
	ExitCode int `json:"exit_code"`

	// Size of stdout output in bytes
	StdoutSize int `json:"stdout_size"`

	// Size of stderr output in bytes
	StderrSize int `json:"stderr_size"`

	// Error message if command failed
	ErrorMessage string `json:"error_message,omitempty"`

	// Working directory where command was executed
	WorkingDirectory string `json:"working_directory"`

	// Environment variables relevant to the command (filtered for security)
	Environment map[string]string `json:"environment,omitempty"`

	// Target file or resource the command operated on
	TargetResource string `json:"target_resource,omitempty"`

	// Result summary or key findings from the command
	ResultSummary string `json:"result_summary,omitempty"`
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // INFO, WARNING, ERROR
	Message   string    `json:"message"`
	Details   string    `json:"details"`
	Error     string    `json:"error"`
}
