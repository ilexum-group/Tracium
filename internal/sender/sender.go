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
	utils.Logger.Info("Preparing to send data to server")

	jsonData, err := json.Marshal(data)
	if err != nil {
		utils.Logger.WithError(err).Error("Failed to marshal data")
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.ServerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		utils.Logger.WithError(err).Error("Failed to create request")
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("User-Agent", "Tracium-Agent/1.0")

	utils.Logger.WithField("url", cfg.ServerURL).Info("Sending request to server")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		utils.Logger.WithError(err).Error("Failed to send request")
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		utils.Logger.WithField("status_code", resp.StatusCode).Error("Server returned non-OK status")
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	utils.Logger.Info("Data sent successfully to server")
	return nil
}
