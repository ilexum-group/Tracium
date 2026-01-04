package main

import (
	"time"

	"github.com/tracium/internal/collector"
	"github.com/tracium/internal/config"
	"github.com/tracium/internal/models"
	"github.com/tracium/internal/sender"
	"github.com/tracium/internal/utils"
)

func main() {
	utils.Logger.Info("Starting Tracium agent")

	// Load configuration
	cfg := config.Load()
	utils.Logger.WithField("server_url", cfg.ServerURL).Info("Configuration loaded")

	// Collect system information
	data := collectData()
	utils.Logger.Info("Data collection completed")

	// Send data to server
	err := sender.SendData(cfg, data)
	if err != nil {
		utils.Logger.WithError(err).Fatal("Failed to send data")
	}

	utils.Logger.Info("Data sent successfully")
}

func collectData() models.SystemData {
	data := models.SystemData{
		Timestamp: time.Now().Unix(),
	}

	// Collect system info
	data.System = collector.CollectSystemInfo()

	// Collect hardware info
	data.Hardware = collector.CollectHardwareInfo()

	// Collect network info
	data.Network = collector.CollectNetworkInfo()

	// Collect security info
	data.Security = collector.CollectSecurityInfo()

	return data
}