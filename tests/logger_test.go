package tests

import (
	"os"
	"strings"
	"testing"

	"github.com/ilexum-group/tracium/internal/logger"
)

func TestRFC5424Logger(t *testing.T) {
	// Initialize the logger
	err := logger.InitDefaultLogger("Tracium", "testhost", "12345")
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Capture stdout to verify log output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test different log levels
	logger.LogInfo("Test info message", map[string]string{"test": "true", "level": "info"})
	logger.LogWarn("Test warning message", map[string]string{"test": "true", "level": "warn"})
	logger.LogError("Test error message", map[string]string{"test": "true", "level": "error"})
	logger.LogDebug("Test debug message", map[string]string{"test": "true", "level": "debug"})

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
	err := logger.InitDefaultLogger("Tracium", "testhost", "12345")
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test logging without metadata
	logger.LogInfo("Simple message", nil)

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

func TestLoggerMultipleMessages(t *testing.T) {
	err := logger.InitDefaultLogger("Tracium", "testhost", "12345")
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Log multiple messages
	logger.LogInfo("First message", map[string]string{"seq": "1"})
	logger.LogInfo("Second message", map[string]string{"seq": "2"})
	logger.LogInfo("Third message", map[string]string{"seq": "3"})

	// Restore stdout
	err = w.Close()
	if err != nil {
		t.Fatalf("Failed to close pipe writer: %v", err)
	}
	os.Stdout = oldStdout

	// Read output
	output := make([]byte, 2048)
	n, _ := r.Read(output)
	logOutput := string(output[:n])

	// Verify all messages are present
	if !strings.Contains(logOutput, "First message") {
		t.Error("Missing first message")
	}
	if !strings.Contains(logOutput, "Second message") {
		t.Error("Missing second message")
	}
	if !strings.Contains(logOutput, "Third message") {
		t.Error("Missing third message")
	}

	t.Logf("Successfully logged %d messages", 3)
}
