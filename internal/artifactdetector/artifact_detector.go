// Package artifactdetector provides signature-based artifact detection and classification
package artifactdetector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ilexum-group/tracium/pkg/models"
)

// File signatures for artifact detection
var (
	// SQLite header signature
	SQLiteSignature = []byte("SQLite format 3")

	// MBOX email file signature
	MBOXSignature = []byte("From ")

	// PST/OST Outlook file signature
	PSTSignature = []byte("!BDN")

	// JSON signature markers
	JSONStartMarkers = []byte("{[")
)

// ArtifactType represents the type of detected artifact
type ArtifactType string

const (
	// Browser artifacts
	ArtifactTypeHistory         ArtifactType = "history"
	ArtifactTypeCookies         ArtifactType = "cookies"
	ArtifactTypeDownloads       ArtifactType = "downloads"
	ArtifactTypeBookmarks       ArtifactType = "bookmarks"
	ArtifactTypeCache           ArtifactType = "cache"
	ArtifactTypeFormAutofill    ArtifactType = "form_autofill"
	ArtifactTypeSearchHistory  ArtifactType = "search_history"
	ArtifactTypeChromiumProfile ArtifactType = "chromium_profile"
	ArtifactTypeChromiumExt    ArtifactType = "chromium_extension"

	// Communication artifacts
	ArtifactTypeEmailAccount    ArtifactType = "email_account"
	ArtifactTypeEmailMessage    ArtifactType = "email_message"
	ArtifactTypeGmailDrafts     ArtifactType = "gmail_drafts"
	ArtifactTypeGmailSent       ArtifactType = "gmail_sent"
	ArtifactTypeGmailTrash      ArtifactType = "gmail_trash"
	ArtifactTypeEmailDefault    ArtifactType = "email_default"
)

// Classifier provides stateless, parallel-safe artifact classification
type Classifier struct {
	fileReader func(path string) ([]byte, error)
}

// NewClassifier creates a new artifact classifier
func NewClassifier() *Classifier {
	return &Classifier{
		fileReader: func(path string) ([]byte, error) {
			return nil, fmt.Errorf("file reader not configured")
		},
	}
}

// SetFileReader sets the custom file reader function
func (c *Classifier) SetFileReader(reader func(path string) ([]byte, error)) {
	c.fileReader = reader
}

// DetectFileType detects the file type based on magic bytes/signatures
func (c *Classifier) DetectFileType(data []byte) ArtifactType {
	if len(data) < 16 {
		return ""
	}

	// Check for SQLite
	if bytes.HasPrefix(data, SQLiteSignature) {
		return ArtifactTypeHistory // Default to history, will be refined by schema inspection
	}

	// Check for MBOX
	if bytes.HasPrefix(data, MBOXSignature) {
		return ArtifactTypeEmailDefault
	}

	// Check for PST/OST
	if bytes.HasPrefix(data, PSTSignature) {
		return ArtifactTypeEmailMessage
	}

	// Check for JSON
	if bytes.HasPrefix(data, JSONStartMarkers) {
		return ArtifactTypeChromiumProfile
	}

	return ""
}

// InspectSQLiteSchema inspects SQLite database schema to classify artifact type
func (c *Classifier) InspectSQLiteSchema(dbPath string) (ArtifactType, error) {
	data, err := c.fileReader(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to read database: %w", err)
	}

	// Verify it's a SQLite file
	if !bytes.HasPrefix(data, SQLiteSignature) {
		return "", fmt.Errorf("not a SQLite database")
	}

	// Common Chromium/SQLite browser database table names
	// that indicate specific artifact types
	tablePatterns := map[ArtifactType][]string{
		ArtifactTypeHistory:        {"urls", "visits", "url", "visit", "moz_places", "place_id"},
		ArtifactTypeCookies:       {"cookies", "cookie", "moz_cookies"},
		ArtifactTypeDownloads:     {"downloads", "download", "download_url_chunks"},
		ArtifactTypeBookmarks:     {"bookmarks", "bookmark", "moz_bookmarks"},
		ArtifactTypeFormAutofill:  {"autofill", "form_autofill", "credit_cards", "webkit_form_history"},
		ArtifactTypeSearchHistory: {"keyword_search_terms", "moz_input_history"},
	}

	// Simple pattern matching on raw data for table names
	// In production, this would use a SQLite library to query sqlite_master
	dataStr := string(data)

	for artifactType, patterns := range tablePatterns {
		for _, pattern := range patterns {
			if strings.Contains(dataStr, pattern) {
				return artifactType, nil
			}
		}
	}

	// Default to history if we can't determine
	return ArtifactTypeHistory, nil
}

// DetectBrowserArtifact classifies a browser artifact file
func (c *Classifier) DetectBrowserArtifact(file models.ForensicFile) (models.ForensicFile, error) {
	result := file

	data, err := c.fileReader(file.Path)
	if err != nil {
		// If we can't read the file, return as-is with generic classification
		result.Category = string(ArtifactTypeHistory)
		return result, nil
	}

	artifactType := c.DetectFileType(data)
	result.Category = string(artifactType)

	// If it's SQLite, inspect schema for more specific classification
	if artifactType == ArtifactTypeHistory || bytes.HasPrefix(data, SQLiteSignature) {
		detectedType, err := c.InspectSQLiteSchema(file.Path)
		if err == nil {
			result.Category = string(detectedType)
		}
	}

	// Additional path-based heuristics for browser type
	filename := strings.ToLower(filepath.Base(file.Path))
	path := strings.ToLower(file.Path)

	// Detect Chrome/Chromium specific files
	if strings.Contains(path, "chrome") || strings.Contains(path, "chromium") {
		result.Browser = "chrome"
		if strings.Contains(filename, "history") {
			result.Category = string(ArtifactTypeHistory)
		} else if strings.Contains(filename, "cookies") {
			result.Category = string(ArtifactTypeCookies)
		} else if strings.Contains(filename, "download") {
			result.Category = string(ArtifactTypeDownloads)
		} else if strings.Contains(filename, "bookmark") {
			result.Category = string(ArtifactTypeBookmarks)
		} else if strings.Contains(filename, "login") || strings.Contains(filename, "autofill") {
			result.Category = string(ArtifactTypeFormAutofill)
		}
	}

	// Detect Firefox specific files
	if strings.Contains(path, "firefox") || strings.Contains(path, "mozilla") {
		result.Browser = "firefox"
		if strings.Contains(filename, "places") {
			result.Category = string(ArtifactTypeHistory)
		} else if strings.Contains(filename, "cookies") {
			result.Category = string(ArtifactTypeCookies)
		}
	}

	// Detect Edge specific files
	if strings.Contains(path, "edge") {
		result.Browser = "edge"
	}

	return result, nil
}

// DetectCommunicationArtifact classifies a communication artifact file
func (c *Classifier) DetectCommunicationArtifact(file models.ForensicFile) (models.ForensicFile, error) {
	result := file

	data, err := c.fileReader(file.Path)
	if err != nil {
		result.Category = string(ArtifactTypeEmailDefault)
		return result, nil
	}

	artifactType := c.DetectFileType(data)
	path := strings.ToLower(file.Path)
	filename := strings.ToLower(filepath.Base(file.Path))

	// Check for Gmail folder structure in path
	if strings.Contains(path, "[gmail]") || strings.Contains(path, "gmail") {
		if strings.Contains(filename, "draft") || strings.Contains(path, "drafts") {
			result.Category = string(ArtifactTypeGmailDrafts)
		} else if strings.Contains(filename, "sent") || strings.Contains(path, "sent mail") {
			result.Category = string(ArtifactTypeGmailSent)
		} else if strings.Contains(filename, "trash") || strings.Contains(path, "trash") {
			result.Category = string(ArtifactTypeGmailTrash)
		} else {
			result.Category = string(ArtifactTypeEmailDefault)
		}
	} else if artifactType == ArtifactTypeEmailDefault {
		// MBOX file detected
		result.Category = string(ArtifactTypeEmailDefault)
	} else if artifactType == ArtifactTypeEmailMessage {
		// PST/OST file detected
		result.Category = string(ArtifactTypeEmailMessage)
	}

	// Check for account files
	accountIndicators := []string{"account", "profile", "identities"}
	for _, indicator := range accountIndicators {
		if strings.Contains(path, indicator) {
			result.Category = string(ArtifactTypeEmailAccount)
			break
		}
	}

	// Try to parse JSON for account detection
	if bytes.HasPrefix(data, JSONStartMarkers) {
		var jsonData map[string]interface{}
		if err := json.Unmarshal(data, &jsonData); err == nil {
			// Check for email-related fields
			if _, hasEmail := jsonData["email"]; hasEmail {
				result.Category = string(ArtifactTypeEmailAccount)
			}
			if _, hasAccountID := jsonData["account_id"]; hasAccountID {
				result.Category = string(ArtifactTypeEmailAccount)
			}
			if _, hasSMTP := jsonData["smtp"]; hasSMTP {
				result.Category = string(ArtifactTypeEmailAccount)
			}
		}
	}

	return result, nil
}

// ClassifyBrowserArtifact classifies a forensic file into the appropriate browser category
func ClassifyBrowserArtifact(file models.ForensicFile) models.ForensicFile {
	// Default file reader that returns empty - to be configured by caller
	result := file

	filename := strings.ToLower(filepath.Base(file.Path))
	path := strings.ToLower(file.Path)

	// Determine browser type
	if strings.Contains(path, "chrome") || strings.Contains(path, "chromium") {
		result.Browser = "chrome"
	} else if strings.Contains(path, "firefox") || strings.Contains(path, "mozilla") {
		result.Browser = "firefox"
	} else if strings.Contains(path, "edge") {
		result.Browser = "edge"
	} else if strings.Contains(path, "opera") {
		result.Browser = "opera"
	} else if strings.Contains(path, "brave") {
		result.Browser = "brave"
	}

	// Classify based on filename patterns
	switch {
	case strings.Contains(filename, "history") || strings.Contains(filename, "places"):
		result.Category = string(ArtifactTypeHistory)
	case strings.Contains(filename, "cookie"):
		result.Category = string(ArtifactTypeCookies)
	case strings.Contains(filename, "download"):
		result.Category = string(ArtifactTypeDownloads)
	case strings.Contains(filename, "bookmark"):
		result.Category = string(ArtifactTypeBookmarks)
	case strings.Contains(filename, "cache") || strings.Contains(filename, "cache2"):
		result.Category = string(ArtifactTypeCache)
	case strings.Contains(filename, "login") || strings.Contains(filename, "autofill") || strings.Contains(filename, "form"):
		result.Category = string(ArtifactTypeFormAutofill)
	case strings.Contains(filename, "search") || strings.Contains(filename, "keyword"):
		result.Category = string(ArtifactTypeSearchHistory)
	case strings.Contains(filename, "extension") || strings.Contains(filename, "extensions"):
		result.Category = string(ArtifactTypeChromiumExt)
	case strings.Contains(filename, "preferences") || strings.Contains(filename, "pref"):
		result.Category = string(ArtifactTypeChromiumProfile)
	default:
		result.Category = "browser_db"
	}

	return result
}

// ClassifyCommunicationArtifact classifies a forensic file into the appropriate communication category
func ClassifyCommunicationArtifact(file models.ForensicFile) models.ForensicFile {
	result := file

	filename := strings.ToLower(filepath.Base(file.Path))
	path := strings.ToLower(file.Path)

	// Detect Gmail folders
	if strings.Contains(path, "[gmail]") || strings.Contains(path, "gmail/all mail") {
		if strings.Contains(filename, "draft") || strings.Contains(path, "drafts") {
			result.Category = string(ArtifactTypeGmailDrafts)
		} else if strings.Contains(filename, "sent") || strings.Contains(path, "sent mail") {
			result.Category = string(ArtifactTypeGmailSent)
		} else if strings.Contains(filename, "trash") || strings.Contains(path, "trash") {
			result.Category = string(ArtifactTypeGmailTrash)
		} else {
			result.Category = string(ArtifactTypeEmailDefault)
		}
	} else if strings.Contains(path, "outlook") || strings.Contains(path, "pst") || strings.Contains(path, "ost") {
		// PST/OST files
		if strings.Contains(filename, "draft") {
			result.Category = string(ArtifactTypeGmailDrafts)
		} else if strings.Contains(filename, "sent") {
			result.Category = string(ArtifactTypeGmailSent)
		} else if strings.Contains(filename, "trash") || strings.Contains(filename, "deleted") {
			result.Category = string(ArtifactTypeGmailTrash)
		} else {
			result.Category = string(ArtifactTypeEmailMessage)
		}
	} else if strings.HasPrefix(filename, "mbox") || strings.Contains(path, "mbox") {
		result.Category = string(ArtifactTypeEmailDefault)
	} else if strings.Contains(path, "account") || strings.Contains(path, "profile") {
		result.Category = string(ArtifactTypeEmailAccount)
	} else {
		result.Category = string(ArtifactTypeEmailDefault)
	}

	return result
}

// IsSQLiteFile checks if the data represents a SQLite database
func IsSQLiteFile(data []byte) bool {
	return len(data) >= 16 && bytes.HasPrefix(data, SQLiteSignature)
}

// IsMBOXFile checks if the data represents an MBOX email file
func IsMBOXFile(data []byte) bool {
	return len(data) >= 5 && bytes.HasPrefix(data, MBOXSignature)
}

// IsPSTFile checks if the data represents a PST/OST file
func IsPSTFile(data []byte) bool {
	return len(data) >= 3 && bytes.HasPrefix(data, PSTSignature)
}

// IsJSONFile checks if the data represents a JSON file
func IsJSONFile(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// CopyFileWithHash copies a file and computes its hash (reader interface version)
func CopyFileWithHash(reader io.Reader, destPath string) ([]byte, int64, error) {
	return nil, 0, fmt.Errorf("not implemented: use os-specific implementation")
}
