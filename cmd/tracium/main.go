// Package main implements the Tracium agent that collects system information and sends it to a remote server.
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
	// Initialize the RFC 5424 compliant logger
	if err := utils.InitDefaultLogger(); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}

	utils.LogInfo("Starting Tracium agent", map[string]string{"version": "1.0.0"})

	// Load configuration
	cfg := config.Load()
	utils.LogInfo("Configuration loaded", map[string]string{"server_url": cfg.ServerURL})

	// Collect system information
	data := collectData()
	utils.LogInfo("Data collection completed", map[string]string{"data_points": "4"}) // system, hardware, network, security

	// Send data to server
	err := sender.SendData(cfg, data)
	if err != nil {
		utils.LogError("Failed to send data", map[string]string{"error": err.Error()})
		return
	}

	utils.LogInfo("Data sent successfully", map[string]string{"status": "completed"})
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
