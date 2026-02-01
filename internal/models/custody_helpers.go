// Package models - Custody Chain helper functions for Tracium
package models

import (
	"crypto/md5"  //nolint:gosec // MD5 required for forensic compatibility
	"crypto/sha1" //nolint:gosec // SHA1 required for forensic compatibility
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

// NewCustodyChainEntry creates a new custody chain entry for Tracium
func NewCustodyChainEntry(caseID, version string) (*CustodyChainEntry, error) {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}

	now := time.Now().UTC()

	entry := &CustodyChainEntry{
		ID:              uuid.New().String(),
		AgentType:       "tracium",
		AgentVersion:    version,
		AgentHostname:   hostname,
		AgentUser:       username,
		StartTimestamp:  now,
		CaseID:          caseID,
		ProcessorStatus: "pending",
		LogEntries:      make([]string, 0),
		CommandHistory:  make([]CommandExecution, 0),
		CustodyHistory:  make([]CustodyTransfer, 0),
		IntegrityStatus: "not_verified",
	}

	// Add initial custody transfer
	initialTransfer := CustodyTransfer{
		ID:                 uuid.New().String(),
		Timestamp:          now,
		Action:             "collected",
		CustodianName:      fmt.Sprintf("%s@%s", username, hostname),
		CustodianRole:      "forensic_agent",
		Location:           hostname,
		Notes:              "System data and forensic artifacts collected by Tracium agent",
		VerificationStatus: "not_performed",
	}
	entry.CustodyHistory = append(entry.CustodyHistory, initialTransfer)

	return entry, nil
}

// AddCommandExecution adds a command execution record to the custody chain
func (c *CustodyChainEntry) AddCommandExecution(cmd CommandExecution) {
	if cmd.ID == "" {
		cmd.ID = uuid.New().String()
	}
	c.CommandHistory = append(c.CommandHistory, cmd)
}

// AddLogEntry adds a log entry to the custody chain
func (c *CustodyChainEntry) AddLogEntry(logEntry string) {
	c.LogEntries = append(c.LogEntries, logEntry)
}

// AddCustodyTransfer adds a custody transfer event to the chain
func (c *CustodyChainEntry) AddCustodyTransfer(transfer CustodyTransfer) {
	if transfer.ID == "" {
		transfer.ID = uuid.New().String()
	}
	if transfer.Timestamp.IsZero() {
		transfer.Timestamp = time.Now().UTC()
	}
	c.CustodyHistory = append(c.CustodyHistory, transfer)
}

// Finalize completes the custody chain entry with final hashes and metadata
func (c *CustodyChainEntry) Finalize(data []byte, itemCount int) error {
	c.EndTimestamp = time.Now().UTC()
	c.Duration = c.EndTimestamp.Sub(c.StartTimestamp).String()
	c.ItemCount = itemCount
	c.TotalSizeBytes = int64(len(data))

	// Calculate all standard hashes
	md5Hash := md5.Sum(data) //nolint:gosec // MD5 required for forensic compatibility
	c.MD5Hash = hex.EncodeToString(md5Hash[:])

	sha1Hash := sha1.Sum(data) //nolint:gosec // SHA1 required for forensic compatibility
	c.SHA1Hash = hex.EncodeToString(sha1Hash[:])

	sha256Hash := sha256.Sum256(data)
	c.SHA256Hash = hex.EncodeToString(sha256Hash[:])

	c.IntegrityStatus = "verified"
	c.IntegrityDetails = fmt.Sprintf("MD5: %s, SHA1: %s, SHA256: %s", c.MD5Hash, c.SHA1Hash, c.SHA256Hash)

	return nil
}

// FinalizeFromReader completes the custody chain by reading and hashing data from a reader
func (c *CustodyChainEntry) FinalizeFromReader(reader io.Reader, itemCount int) error {
	c.EndTimestamp = time.Now().UTC()
	c.Duration = c.EndTimestamp.Sub(c.StartTimestamp).String()
	c.ItemCount = itemCount

	// Create hash writers
	md5Hash := md5.New()   //nolint:gosec // MD5 required for forensic compatibility
	sha1Hash := sha1.New() //nolint:gosec // SHA1 required for forensic compatibility
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

	c.IntegrityStatus = "verified"
	c.IntegrityDetails = fmt.Sprintf("MD5: %s, SHA1: %s, SHA256: %s", c.MD5Hash, c.SHA1Hash, c.SHA256Hash)

	return nil
}

// MarkTransmitted marks the custody chain as transmitted to Processor
func (c *CustodyChainEntry) MarkTransmitted(processorURL string, response *ProcessorResponse) {
	c.ProcessorURL = processorURL
	c.ProcessorSentAt = time.Now().UTC()
	c.ProcessorStatus = "sent"

	if response != nil {
		if response.TimeAnalysisID != "" {
			c.TimeAnalysisRef = response.TimeAnalysisID
		}
		if response.ReportID != "" {
			c.ReportRef = response.ReportID
		}
	}

	// Add custody transfer for transmission
	transfer := CustodyTransfer{
		ID:                 uuid.New().String(),
		Timestamp:          time.Now().UTC(),
		Action:             "transmitted",
		CustodianName:      "processor",
		CustodianRole:      "evidence_processor",
		FromCustodian:      fmt.Sprintf("%s@%s", c.AgentUser, c.AgentHostname),
		Location:           processorURL,
		Notes:              "System data transmitted to Processor for analysis",
		VerificationHash:   c.SHA256Hash,
		VerificationStatus: "verified",
	}
	c.AddCustodyTransfer(transfer)
}

// MarkTransmissionFailed marks the custody chain as failed transmission
func (c *CustodyChainEntry) MarkTransmissionFailed(processorURL string, err error) {
	c.ProcessorURL = processorURL
	c.ProcessorSentAt = time.Now().UTC()
	c.ProcessorStatus = "failed"
	c.ProcessorError = err.Error()
}

// ToJSON serializes the custody chain entry to JSON
func (c *CustodyChainEntry) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// FromJSON deserializes a custody chain entry from JSON
func FromJSON(data []byte) (*CustodyChainEntry, error) {
	var entry CustodyChainEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal custody chain: %w", err)
	}
	return &entry, nil
}

// Validate validates the custody chain entry for completeness and integrity
func (c *CustodyChainEntry) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("custody chain ID is required")
	}
	if c.AgentType == "" {
		return fmt.Errorf("agent type is required")
	}
	if c.AgentVersion == "" {
		return fmt.Errorf("agent version is required")
	}
	if c.CaseID == "" {
		return fmt.Errorf("case ID is required")
	}
	if c.SHA256Hash == "" {
		return fmt.Errorf("SHA256 hash is required for integrity verification")
	}
	if len(c.CustodyHistory) == 0 {
		return fmt.Errorf("custody history must have at least one entry")
	}
	return nil
}

// GenerateTimelineFromTracium generates timeline entries from Tracium forensic data
func GenerateTimelineFromTracium(data *SystemData) []TimelineEntry {
	timeline := make([]TimelineEntry, 0)

	// Add recent files timeline
	for _, file := range data.Forensics.RecentFiles {
		timeline = append(timeline, TimelineEntry{
			ID:            uuid.New().String(),
			Timestamp:     time.Unix(file.AccessedTime, 0).UTC(),
			TimestampType: "accessed",
			Source:        file.Source,
			Description:   fmt.Sprintf("Recent file accessed: %s", file.FileName),
			ArtifactPath:  file.FilePath,
			ArtifactType:  "file",
		})
	}

	// Add command history timeline
	for _, cmd := range data.Forensics.CommandHistory {
		var timestamp time.Time
		if cmd.Timestamp > 0 {
			timestamp = time.Unix(cmd.Timestamp, 0).UTC()
		} else {
			timestamp = time.Unix(data.Timestamp, 0).UTC()
		}

		timeline = append(timeline, TimelineEntry{
			ID:            uuid.New().String(),
			Timestamp:     timestamp,
			TimestampType: "executed",
			Source:        "command_history",
			Description:   fmt.Sprintf("Command executed in %s: %s", cmd.Shell, cmd.Command),
			ArtifactPath:  cmd.Command,
			ArtifactType:  "command",
			Metadata: map[string]interface{}{
				"shell":    cmd.Shell,
				"line_num": cmd.LineNum,
			},
		})
	}

	// Add recent downloads timeline
	for _, download := range data.Forensics.RecentDownloads {
		timeline = append(timeline, TimelineEntry{
			ID:            uuid.New().String(),
			Timestamp:     time.Unix(download.AccessedTime, 0).UTC(),
			TimestampType: "accessed",
			Source:        download.Source,
			Description:   fmt.Sprintf("File downloaded: %s", download.FileName),
			ArtifactPath:  download.FilePath,
			ArtifactType:  "file",
		})
	}

	// Add deleted files (recycle bin) timeline
	for _, deleted := range data.Forensics.RecycleBin {
		if deleted.DeletedTime > 0 {
			timeline = append(timeline, TimelineEntry{
				ID:            uuid.New().String(),
				Timestamp:     time.Unix(deleted.DeletedTime, 0).UTC(),
				TimestampType: "deleted",
				Source:        "recycle_bin",
				Description:   fmt.Sprintf("File deleted: %s", deleted.FileName),
				ArtifactPath:  deleted.OriginalPath,
				ArtifactType:  "file",
				Size:          deleted.Size,
			})
		}
	}

	// Add USB device connection timeline
	for _, usb := range data.Forensics.USBHistory {
		if usb.FirstSeen != "" {
			// Try to parse the timestamp (format may vary)
			if t, err := time.Parse(time.RFC3339, usb.FirstSeen); err == nil {
				timeline = append(timeline, TimelineEntry{
					ID:            uuid.New().String(),
					Timestamp:     t,
					TimestampType: "connected",
					Source:        "usb_history",
					Description:   fmt.Sprintf("USB device connected: %s", usb.Description),
					ArtifactPath:  usb.DeviceID,
					ArtifactType:  "device",
					Metadata: map[string]interface{}{
						"vendor_id":     usb.VendorID,
						"product_id":    usb.ProductID,
						"serial_number": usb.SerialNumber,
					},
				})
			}
		}
	}

	// Add prefetch execution timeline
	for _, prefetch := range data.Forensics.PrefetchFiles {
		if prefetch.LastRunTime > 0 {
			timeline = append(timeline, TimelineEntry{
				ID:            uuid.New().String(),
				Timestamp:     time.Unix(prefetch.LastRunTime, 0).UTC(),
				TimestampType: "executed",
				Source:        "prefetch",
				Description:   fmt.Sprintf("Program executed: %s (run count: %d)", prefetch.Executable, prefetch.RunCount),
				ArtifactPath:  prefetch.Executable,
				ArtifactType:  "executable",
				Metadata: map[string]interface{}{
					"run_count":    prefetch.RunCount,
					"files_loaded": prefetch.FilesLoaded,
				},
			})
		}
	}

	return timeline
}
