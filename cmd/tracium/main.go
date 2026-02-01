// Package main implements the Tracium agent that collects system information and sends it to a remote server.
package main

import (
	"os"
	"time"

	"github.com/ilexum-group/tracium/internal/collector"
	"github.com/ilexum-group/tracium/internal/config"
	"github.com/ilexum-group/tracium/internal/forensics"
	"github.com/ilexum-group/tracium/internal/models"
	"github.com/ilexum-group/tracium/internal/sender"
	"github.com/ilexum-group/tracium/internal/utils"
)

func main() {
	// Initialize the RFC 5424 compliant logger
	if err := utils.InitDefaultLogger(); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}

	utils.LogInfo("Starting Tracium agent", map[string]string{"version": "1.0.0"})

	// Load configuration from CLI flags
	cfg, err := config.LoadFromFlags(os.Args[1:])
	if err != nil {
		utils.LogError("Failed to parse flags", map[string]string{"error": err.Error()})
		os.Exit(1)
	}

	// Disk imaging and analysis is now performed by Bitex. Tracium does not access block devices directly.

	utils.LogInfo("Configuration loaded", map[string]string{"server_url": cfg.ServerURL, "case_id": cfg.CaseID})

	// Collect system information
	data := collectData(cfg)

	// Collect forensics data (optional based on flag)
	if cfg.EnableForensics {
		utils.LogInfo("Collecting forensics data", map[string]string{})
		data.Forensics = forensics.CollectForensicsData()
	}

	utils.LogInfo("Data collection completed", map[string]string{"data_points": "7"}) // system, hardware, network, security, forensics, disk images, disk analysis

	// Disk analysis is now performed by Bitex. Tracium only consumes results from Bitex.

	// Collect logs before sending
	data.Logs = utils.GetLogs()

	// Send data and disk images to server
	err = sender.SendData(cfg, data)
	if err != nil {
		utils.LogError("Failed to send data", map[string]string{"error": err.Error()})
		return
	}

	utils.LogInfo("Data sent successfully", map[string]string{"status": "completed"})
}

func collectData(cfg *config.Config) models.SystemData {
	data := models.SystemData{
		Timestamp: time.Now().Unix(),
		CaseID:    cfg.CaseID,
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
