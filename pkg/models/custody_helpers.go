// Package models - Custody Chain helper functions for Bitex
package models

import (
	"crypto/md5"  //nolint:gosec // MD5 used for forensic verification, not security
	"crypto/sha1" //nolint:gosec // SHA1 used for forensic verification, not security
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Constructor
// ============================================================================

// NewCustodyChainEntry creates a new custody chain entry with the specified case and agent information.
// Parameters:
//   - agentType: Type of forensic agent (e.g., "bitex", "evidex", "tracium")
//   - version: Version of the agent creating this entry
//
// Returns a new CustodyChainEntry instance with initialized arrays and timestamps.
func NewCustodyChainEntry(agentType, version string) (*CustodyChainEntry, error) {
	now := time.Now().UTC()

	entry := &CustodyChainEntry{
		ID:             uuid.New().String(),
		AgentType:      agentType,
		AgentVersion:   version,
		StartTimestamp: now,
		LogEntries:     make([]LogEntry, 0),
		CommandHistory: make([]CommandExecution, 0),
	}

	return entry, nil
}

// ============================================================================
// Public Methods
// ============================================================================

// FinalizeFromReader completes the custody chain by reading and hashing data from a reader.
// This method:
//   - Sets the end timestamp and calculates duration
//   - Reads the complete evidence data from the provided reader
//   - Calculates MD5, SHA1, and SHA256 hashes simultaneously
//   - Sets the total size and hash values
//
// Parameters:
//   - reader: io.Reader containing the complete evidence data
//   - itemCount: Number of items/files collected in this evidence package
//
// Returns an error if reading or hashing fails.
func (c *CustodyChainEntry) FinalizeFromReader(reader io.Reader, itemCount int) error {
	c.EndTimestamp = time.Now().UTC()
	c.Duration = c.EndTimestamp.Sub(c.StartTimestamp).String()
	c.ItemCount = itemCount

	// Create hash writers
	md5Hash := md5.New()   //nolint:gosec // G401: MD5 for forensic verification, not security
	sha1Hash := sha1.New() //nolint:gosec // G401: SHA1 for forensic verification, not security
	sha256Hash := sha256.New()

	// Use MultiWriter to hash while reading
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	// Read and hash data
	size, err := io.Copy(multiWriter, reader)
	if err != nil {
		return fmt.Errorf("failed to read and hash data: %w", err)
	}

	c.TotalSizeBytes = size
	c.MD5Hash = hex.EncodeToString(md5Hash.Sum(nil))
	c.SHA1Hash = hex.EncodeToString(sha1Hash.Sum(nil))
	c.SHA256Hash = hex.EncodeToString(sha256Hash.Sum(nil))

	return nil
}

// LogCommand logs a command execution to the custody chain command history.
// Parameters:
//   - id: Unique identifier for the command execution
//   - command: Command name that was executed
//   - args: Command-line arguments passed to the command
//   - startTime: UTC timestamp when command started
//   - endTime: UTC timestamp when command completed
//   - exitCode: Exit code returned by the command
//   - err: Error object if command failed (can be nil)
//   - workingDirectory: Directory where the command was executed
//   - targetResource: File or resource the command operated on
func (c *CustodyChainEntry) LogCommand(id, command string, args []string, startTime, endTime time.Time, exitCode int, err error, workingDirectory, targetResource string) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	cmd := CommandExecution{
		ID:               id,
		Command:          command,
		Arguments:        args,
		StartTime:        startTime,
		EndTime:          endTime,
		Duration:         endTime.Sub(startTime).String(),
		ExitCode:         exitCode,
		ErrorMessage:     errMsg,
		WorkingDirectory: workingDirectory,
		TargetResource:   targetResource,
	}
	c.CommandHistory = append(c.CommandHistory, cmd)
}

// LogError logs an error message to the custody chain.
// Parameters:
//   - operation: Name or identifier of the operation that failed
//   - message: Error message to log
//   - err: Error object (can be nil)
func (c *CustodyChainEntry) LogError(operation, message string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     LogLevelError,
		Message:   message,
		Details:   operation,
		Error:     errMsg,
	}
	c.LogEntries = append(c.LogEntries, entry)
}

// LogInfo logs an informational message to the custody chain.
// Parameters:
//   - operation: Name or identifier of the operation being performed
//   - message: Informational message to log
func (c *CustodyChainEntry) LogInfo(operation, message string) {
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     LogLevelInfo,
		Message:   message,
		Details:   operation,
	}
	c.LogEntries = append(c.LogEntries, entry)
}

// LogWarning logs a warning message to the custody chain.
// Parameters:
//   - operation: Name or identifier of the operation being performed
//   - message: Warning message to log
func (c *CustodyChainEntry) LogWarning(operation, message string) {
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     LogLevelWarning,
		Message:   message,
		Details:   operation,
	}
	c.LogEntries = append(c.LogEntries, entry)
}

// SetAgentHostname sets the hostname of the agent executing the custody chain.
// This method allows updating the hostname after the custody chain entry has been created.
// Parameters:
//   - hostname: The hostname of the machine running the forensic agent
func (c *CustodyChainEntry) SetAgentHostname(hostname string) {
	c.AgentHostname = hostname
}

// SetAgentUser sets the username of the agent executing the custody chain.
// This method allows updating the username after the custody chain entry has been created.
// Parameters:
//   - username: The username of the user running the forensic agent
func (c *CustodyChainEntry) SetAgentUser(username string) {
	c.AgentUser = username
}
