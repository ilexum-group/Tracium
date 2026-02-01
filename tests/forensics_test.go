// Package tests provides test cases for the forensics package.
package tests

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ilexum/tracium/internal/forensics"
)

// TestCollectForensicsData tests the collection of forensic data
func TestCollectForensicsData(t *testing.T) {
	// Initialize logger for tests
	_ = os.Setenv("TRACIUM_LOG_LEVEL", "error") // Suppress logs during tests

	data := forensics.CollectForensicsData()

	// Verify structure exists
	if data.CollectionErrors == nil {
		t.Error("CollectionErrors should be initialized")
	}

	// Forensics collection may or may not find data depending on the system
	// Just verify it doesn't panic and returns a valid structure
	t.Logf("Browser DB files: %d", len(data.BrowserDBFiles))
	t.Logf("Recent files: %d", len(data.RecentFiles))
	t.Logf("Command history: %d", len(data.CommandHistory))
	t.Logf("ARP cache entries: %d", len(data.NetworkHistory.ARPCache))
	t.Logf("DNS cache entries: %d", len(data.NetworkHistory.DNSCache))
	t.Logf("Collection errors: %d", len(data.CollectionErrors))
}

// TestBrowserDBFileCollection tests browser DB file collection
func TestBrowserDBFileCollection(t *testing.T) {
	// This test verifies that browser DB file collection doesn't panic
	// Actual data depends on the system and whether browsers are installed

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Browser DB collection panicked: %v", r)
		}
	}()

	data := forensics.CollectForensicsData()

	// Verify browser DB files have correct fields
	for _, file := range data.BrowserDBFiles {
		if file.Browser == "" {
			t.Error("Browser field should not be empty")
		}
		if file.Path == "" {
			t.Error("Path field should not be empty")
		}
	}
}

// TestCommandHistoryCollection tests command history collection
func TestCommandHistoryCollection(t *testing.T) {
	// Create a temporary bash history file for testing
	if runtime.GOOS != "windows" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			t.Skip("Cannot get user home directory")
		}

		historyPath := filepath.Join(homeDir, ".bash_history")
		if _, err := os.Stat(historyPath); os.IsNotExist(err) {
			// Create a dummy history file
			content := "ls -la\ncd /tmp\npwd\n"
			if err := os.WriteFile(historyPath, []byte(content), 0600); err != nil {
				t.Skip("Cannot create test bash history")
			}
			defer func() {
				if err := os.Remove(historyPath); err != nil {
					t.Logf("Failed to remove test bash history: %v", err)
				}
			}()
		}
	}

	data := forensics.CollectForensicsData()

	// On systems with command history, verify entries are collected
	if len(data.CommandHistory) > 0 {
		for _, cmd := range data.CommandHistory {
			if cmd.Shell == "" {
				t.Error("Shell field should not be empty")
			}
			if cmd.Command == "" {
				t.Error("Command field should not be empty")
			}
			if cmd.LineNum < 1 {
				t.Error("LineNum should be at least 1")
			}
		}
	}
}

// TestNetworkHistoryCollection tests network history collection
func TestNetworkHistoryCollection(t *testing.T) {
	data := forensics.CollectForensicsData()

	// Network history should have ARP and DNS cache structures
	if data.NetworkHistory.ARPCache == nil {
		t.Error("ARPCache should be initialized")
	}

	if data.NetworkHistory.DNSCache == nil {
		t.Error("DNSCache should be initialized")
	}

	// Verify ARP entries have valid fields
	for _, entry := range data.NetworkHistory.ARPCache {
		if entry.IPAddress == "" {
			t.Error("ARP entry should have IP address")
		}
		// MAC address might be empty on some systems
	}

	// Verify DNS entries have valid fields
	for _, entry := range data.NetworkHistory.DNSCache {
		if entry.Hostname == "" {
			t.Error("DNS entry should have hostname")
		}
		if len(entry.IPAddress) == 0 {
			t.Error("DNS entry should have at least one IP address")
		}
	}
}

// TestRecentFilesCollection tests recent files collection
func TestRecentFilesCollection(t *testing.T) {
	data := forensics.CollectForensicsData()

	// Verify recent files structure
	for _, file := range data.RecentFiles {
		if file.FilePath == "" {
			t.Error("FilePath should not be empty")
		}
		if file.FileName == "" {
			t.Error("FileName should not be empty")
		}
		if file.Source == "" {
			t.Error("Source should not be empty")
		}
	}
}

// TestForensicsDataIntegrity tests that forensics data maintains integrity
func TestForensicsDataIntegrity(t *testing.T) {
	// Collect data twice to ensure consistency
	data1 := forensics.CollectForensicsData()
	data2 := forensics.CollectForensicsData()

	// The number of entries should be similar (allowing for small differences due to timing)
	// This is a sanity check, not a strict equality test

	if len(data1.CommandHistory) > 0 && len(data2.CommandHistory) == 0 {
		t.Error("Command history collection is inconsistent")
	}

	t.Logf("First collection: %d browser DBs, %d commands", len(data1.BrowserDBFiles), len(data1.CommandHistory))
	t.Logf("Second collection: %d browser DBs, %d commands", len(data2.BrowserDBFiles), len(data2.CommandHistory))
}

// TestForensicsErrorHandling tests that forensics collection handles errors gracefully
func TestForensicsErrorHandling(t *testing.T) {
	// Change to a non-existent directory to trigger some errors
	originalHome := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		originalHome = os.Getenv("USERPROFILE")
	}

	// Set invalid paths
	_ = os.Setenv("HOME", "/nonexistent/path/to/nowhere")
	_ = os.Setenv("USERPROFILE", "C:\\nonexistent\\path\\to\\nowhere")
	_ = os.Setenv("LOCALAPPDATA", "C:\\nonexistent\\path\\to\\nowhere")
	_ = os.Setenv("APPDATA", "C:\\nonexistent\\path\\to\\nowhere")

	defer func() {
		// Restore original environment
		if runtime.GOOS == "windows" {
			_ = os.Setenv("USERPROFILE", originalHome)
		} else {
			_ = os.Setenv("HOME", originalHome)
		}
	}()

	// Should not panic even with invalid paths
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Forensics collection panicked with invalid paths: %v", r)
		}
	}()

	data := forensics.CollectForensicsData()

	// Should return empty collections but not fail
	if data.CollectionErrors == nil {
		t.Error("CollectionErrors should be initialized")
	}

	t.Logf("Collected with invalid paths: %d errors", len(data.CollectionErrors))
}
