// Package sender handles sending collected data to the remote server
package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ilexum-group/tracium/internal/logger"
	"github.com/ilexum-group/tracium/pkg/models"
)

// Sender handles sending collected data to the remote server
type Sender struct {
	serverURL  string
	authToken  string
	httpClient *http.Client
}

// New creates a new Sender instance
func New(serverURL, authToken string) *Sender {
	return &Sender{
		serverURL:  serverURL,
		authToken:  authToken,
		httpClient: &http.Client{},
	}
}

// SendData sends the collected data to the server
func (s *Sender) SendData(data models.SystemData) error {
	logger.LogInfo("Preparing to send data to server", map[string]string{"url": s.serverURL})

	// Send data as JSON payload
	return s.sendJSONPayload(data)
}

// sendJSONPayload sends data as a single JSON payload
func (s *Sender) sendJSONPayload(data models.SystemData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.LogError("Failed to marshal data", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	contentLength := len(jsonData)
	logger.LogDebug("Sending JSON payload", map[string]string{
		"content_length": fmt.Sprintf("%d bytes", contentLength),
		"size_mb":        fmt.Sprintf("%.2f MB", float64(contentLength)/1024/1024),
	})

	return s.sendHTTPRequest(bytes.NewBuffer(jsonData), contentLength, "application/json")
}

// sendHTTPRequest performs the actual HTTP request with proper headers
func (s *Sender) sendHTTPRequest(body io.Reader, contentLength int, contentType string) error {
	req, err := http.NewRequest("POST", s.serverURL, body)
	if err != nil {
		logger.LogError("Failed to create request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	req.Header.Set("User-Agent", "Tracium-Agent/1.0")
	req.ContentLength = int64(contentLength)

	logger.LogDebug("Sending HTTP request", map[string]string{
		"method":            "POST",
		"content_type":      contentType,
		"content_length":    fmt.Sprintf("%d", contentLength),
		"content_length_mb": fmt.Sprintf("%.2f", float64(contentLength)/1024/1024),
	})

	resp, err := s.httpClient.Do(req)
	if err != nil {
		logger.LogError("Failed to send request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.LogError("Failed to close response body", map[string]string{"error": err.Error()})
		}
	}()

	if resp.StatusCode != http.StatusOK {
		logger.LogWarn("Server returned non-OK status", map[string]string{"status_code": fmt.Sprintf("%d", resp.StatusCode)})
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}
