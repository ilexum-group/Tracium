// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// ArtifactParser handles parsing of forensic artifact files
type ArtifactParser struct{}

// NewArtifactParser creates a new ArtifactParser
func NewArtifactParser() *ArtifactParser {
	return &ArtifactParser{}
}

// ParseResult contains the result of parsing an artifact
type ParseResult struct {
	Format     string // "json", "text", "base64"
	Content    string // Parsed content
	TableCount int    // For SQLite, number of tables
	Error      string // Error message if parsing failed
}

// DetectAndParse detects file type and parses accordingly
func (p *ArtifactParser) DetectAndParse(data []byte, filename string) *ParseResult {
	// Check for SQLite magic bytes
	if isSQLite(data) {
		return p.parseSQLite(data)
	}

	// Check for JSON
	if isJSON(data) {
		return p.parseJSON(data)
	}

	// Check for text (printable ASCII + common chars)
	if isText(data) {
		return p.parseText(data)
	}

	// Default: base64 encode
	return p.toBase64(data)
}

func isSQLite(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	// SQLite magic bytes: "SQLite format 3\000"
	return bytes.Equal(data[:16], []byte("SQLite format 3\x00"))
}

func isJSON(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func isText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Check if majority is printable text
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b < 127) {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.8
}

func (p *ArtifactParser) parseSQLite(data []byte) *ParseResult {
	result := &ParseResult{Format: "json"}

	// Create a temporary file for the SQLite database
	tmpFile, err := os.CreateTemp("", "tracium_sqlite_*.db")
	if err != nil {
		result.Error = fmt.Sprintf("failed to create temp file: %v", err)
		return result
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	// Write data to temp file
	if _, err := tmpFile.Write(data); err != nil {
		result.Error = fmt.Sprintf("failed to write temp file: %v", err)
		return result
	}
	_ = tmpFile.Close()

	// Open SQLite database
	db, err := sql.Open("sqlite3", tmpPath)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open SQLite: %v", err)
		return result
	}
	defer func() { _ = db.Close() }()

	// Get list of tables
	tableQuery := "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
	rows, err := db.Query(tableQuery)
	if err != nil {
		result.Error = fmt.Sprintf("failed to query tables: %v", err)
		return result
	}

	tables := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			tables = append(tables, name)
		}
	}
	_ = rows.Close()
	result.TableCount = len(tables)

	// Build output with all tables
	output := make(map[string]interface{})

	for _, table := range tables {
		// Limit rows to avoid huge output
		query := fmt.Sprintf("SELECT * FROM [%s] LIMIT 100", table)
		rows, err := db.Query(query)
		if err != nil {
			continue
		}

		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			continue
		}

		rowData := make([]map[string]interface{}, 0)
		rowCount := 0
		for rows.Next() {
			if rowCount >= 100 {
				break
			}
			values := make([]interface{}, len(columns))
			valuePtrs := make([]interface{}, len(columns))
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				continue
			}

			row := make(map[string]interface{})
			for i, col := range columns {
				row[col] = values[i]
			}
			rowData = append(rowData, row)
			rowCount++
		}
		_ = rows.Close()

		if len(rowData) > 0 {
			output[table] = rowData
		}
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		result.Error = fmt.Sprintf("failed to marshal JSON: %v", err)
		return result
	}

	result.Content = string(jsonData)
	return result
}

func (p *ArtifactParser) parseJSON(data []byte) *ParseResult {
	result := &ParseResult{Format: "text"}

	// Pretty print JSON
	var jsonObj interface{}
	if err := json.Unmarshal(data, &jsonObj); err != nil {
		result.Error = fmt.Sprintf("invalid JSON: %v", err)
		return result
	}

	prettyJSON, err := json.MarshalIndent(jsonObj, "", "  ")
	if err != nil {
		result.Error = fmt.Sprintf("failed to format JSON: %v", err)
		return result
	}

	result.Content = string(prettyJSON)
	return result
}

func (p *ArtifactParser) parseText(data []byte) *ParseResult {
	return &ParseResult{
		Format:  "text",
		Content: string(data),
	}
}

func (p *ArtifactParser) toBase64(data []byte) *ParseResult {
	return &ParseResult{
		Format:  "base64",
		Content: base64.StdEncoding.EncodeToString(data),
	}
}

// ParseFileFromReader parses an artifact from an io.Reader
func (p *ArtifactParser) ParseFileFromReader(reader io.Reader, filename string) *ParseResult {
	data, err := io.ReadAll(reader)
	if err != nil {
		return &ParseResult{Error: fmt.Sprintf("failed to read: %v", err)}
	}

	return p.DetectAndParse(data, filename)
}

// GetFileType returns a human-readable file type description
func GetFileType(data []byte, filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	switch {
	case isSQLite(data):
		return "SQLite Database"
	case isJSON(data):
		return "JSON File"
	case isText(data):
		if ext == ".log" {
			return "Log File"
		}
		if ext == ".xml" {
			return "XML File"
		}
		if ext == ".html" || ext == ".htm" {
			return "HTML File"
		}
		return "Text File"
	default:
		if ext == ".db" {
			return "Database"
		}
		if ext == ".dat" {
			return "Data File"
		}
		return "Binary File"
	}
}
