package main

import (
	"os"
	"strings"
	"testing"

	"github.com/tracium/internal/utils"
)

func TestRFC5424Logger(t *testing.T) {
	// Initialize the logger
	err := utils.InitDefaultLogger()
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Capture stdout to verify log output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test different log levels
	utils.LogInfo("Test info message", map[string]string{"test": "true", "level": "info"})
	utils.LogWarn("Test warning message", map[string]string{"test": "true", "level": "warn"})
	utils.LogError("Test error message", map[string]string{"test": "true", "level": "error"})
	utils.LogDebug("Test debug message", map[string]string{"test": "true", "level": "debug"})

	// Restore stdout
	err = w.Close()
	if err != nil {
		t.Fatalf("Failed to close pipe writer: %v", err)
	}
	os.Stdout = oldStdout

	// Read captured output
	output := make([]byte, 1024)
	n, _ := r.Read(output)
	logOutput := string(output[:n])

	// Verify RFC 5424 format elements
	expectedElements := []string{
		"<14>1",       // Priority for user.info (1*8 + 6 = 14)
		"Tracium",     // App name
		"[meta@1",     // Structured data start
		`test="true"`, // Test metadata
	}

	for _, element := range expectedElements {
		if !strings.Contains(logOutput, element) {
			t.Errorf("Expected log output to contain '%s', but it didn't. Output: %s", element, logOutput)
		}
	}

	t.Logf("Logger test passed. Sample output:\n%s", logOutput)
}

func TestLoggerWithoutMetadata(t *testing.T) {
	err := utils.InitDefaultLogger()
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test logging without metadata
	utils.LogInfo("Simple message", nil)

	// Restore stdout
	err = w.Close()
	if err != nil {
		t.Fatalf("Failed to close pipe writer: %v", err)
	}
	os.Stdout = oldStdout

	// Read output
	output := make([]byte, 512)
	n, _ := r.Read(output)
	logOutput := string(output[:n])

	// Should still contain basic RFC 5424 format
	if !strings.Contains(logOutput, "<14>1") {
		t.Errorf("Expected RFC 5424 priority format, got: %s", logOutput)
	}

	if !strings.Contains(logOutput, "Simple message") {
		t.Errorf("Expected message content, got: %s", logOutput)
	}
}
