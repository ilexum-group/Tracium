// Package sender handles sending collected data to the remote server
package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ilexum-group/tracium/internal/config"
	"github.com/ilexum-group/tracium/internal/models"
	"github.com/ilexum-group/tracium/internal/utils"
)

const (
	// MaxPayloadSize defines the maximum JSON payload size before chunking (100 MB)
	MaxPayloadSize = 100 * 1024 * 1024
)

// SendData sends the collected data to the server
func SendData(cfg *config.Config, data models.SystemData) error {
	utils.LogInfo("Preparing to send data to server", map[string]string{"url": cfg.ServerURL})

	// Send data as JSON payload
	return sendJSONPayload(cfg, data)
}

// sendJSONPayload sends data as a single JSON payload
func sendJSONPayload(cfg *config.Config, data models.SystemData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		utils.LogError("Failed to marshal data", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	contentLength := len(jsonData)
	utils.LogDebug("Sending JSON payload", map[string]string{
		"content_length": fmt.Sprintf("%d bytes", contentLength),
		"size_mb":        fmt.Sprintf("%.2f MB", float64(contentLength)/1024/1024),
	})

	return sendHTTPRequest(cfg, bytes.NewBuffer(jsonData), contentLength, "application/json")
}

// sendHTTPRequest performs the actual HTTP request with proper headers
func sendHTTPRequest(cfg *config.Config, body io.Reader, contentLength int, contentType string) error {
	req, err := http.NewRequest("POST", cfg.ServerURL, body)
	if err != nil {
		utils.LogError("Failed to create request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("User-Agent", "Tracium-Agent/1.0")
	req.ContentLength = int64(contentLength)

	utils.LogDebug("Sending HTTP request", map[string]string{
		"method":            "POST",
		"content_type":      contentType,
		"content_length":    fmt.Sprintf("%d", contentLength),
		"content_length_mb": fmt.Sprintf("%.2f", float64(contentLength)/1024/1024),
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("Failed to send request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			utils.LogError("Failed to close response body", map[string]string{"error": err.Error()})
		}
	}()

	if resp.StatusCode != http.StatusOK {
		utils.LogWarn("Server returned non-OK status", map[string]string{"status_code": fmt.Sprintf("%d", resp.StatusCode)})
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}
