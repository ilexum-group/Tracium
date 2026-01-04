// Package main implements the Tracium agent that collects system information and sends it to a remote server.
package main

import (
	"os"
	"time"

	"github.com/tracium/internal/collector"
	"github.com/tracium/internal/config"
	"github.com/tracium/internal/diskimaging"
	"github.com/tracium/internal/forensics"
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

	// Collect forensics data (optional based on environment variable)
	if os.Getenv("TRACIUM_ENABLE_FORENSICS") != "false" {
		utils.LogInfo("Collecting forensics data", map[string]string{})
		data.Forensics = forensics.CollectForensicsData()
	}

	utils.LogInfo("Data collection completed", map[string]string{"data_points": "6"}) // system, hardware, network, security, forensics, disk images

	// Create disk images (optional based on environment variable)
	if os.Getenv("TRACIUM_ENABLE_DISK_IMAGING") == "true" {
		collectDiskImages(&data)
	}

	// Collect logs before sending
	data.Logs = utils.GetLogs()

	// Send data and disk images to server
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

func collectDiskImages(data *models.SystemData) {
	utils.LogInfo("Starting disk imaging process", map[string]string{})

	// Get temporary directory for disk images
	imageOutputDir := os.TempDir()
	if customDir := os.Getenv("TRACIUM_IMAGE_OUTPUT_DIR"); customDir != "" {
		imageOutputDir = customDir
	}

	// For now, create image of root disk on Linux/macOS or system drive on Windows
	// In a real implementation, enumerate all available disks
	diskPath := "/"
	if os.Getenv("TRACIUM_DISK_PATH") != "" {
		diskPath = os.Getenv("TRACIUM_DISK_PATH")
	}

	// Attempt to create disk image
	diskImage, err := diskimaging.CreateDiskImage(diskPath, imageOutputDir)
	if err != nil {
		utils.LogError("Failed to create disk image", map[string]string{"disk": diskPath, "error": err.Error()})
		return
	}

	data.DiskImages = append(data.DiskImages, *diskImage)
	utils.LogInfo("Disk image created successfully", map[string]string{
		"disk":  diskPath,
		"image": diskImage.ImagePath,
		"hash":  diskImage.ImageHash,
	})
}
