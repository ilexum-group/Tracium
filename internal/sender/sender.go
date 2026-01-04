// Package sender handles sending collected data to the remote server
package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tracium/internal/config"
	"github.com/tracium/internal/models"
	"github.com/tracium/internal/utils"
)

// SendData sends the collected data to the server
func SendData(cfg *config.Config, data models.SystemData) error {
	utils.LogInfo("Preparing to send data to server", map[string]string{"url": cfg.ServerURL})

	jsonData, err := json.Marshal(data)
	if err != nil {
		utils.LogError("Failed to marshal data", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.ServerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		utils.LogError("Failed to create request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("User-Agent", "Tracium-Agent/1.0")

	utils.LogDebug("Sending HTTP request", map[string]string{"method": "POST", "content_length": fmt.Sprintf("%d", len(jsonData))})

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

	utils.LogInfo("Data sent successfully to server", map[string]string{"status_code": fmt.Sprintf("%d", resp.StatusCode)})
	return nil
}
