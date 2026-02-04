// Package main implements the Tracium agent that collects system information and sends it to a remote server.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ilexum-group/tracium/internal/acquisition"
	"github.com/ilexum-group/tracium/internal/config"
	"github.com/ilexum-group/tracium/internal/forensics"
	"github.com/ilexum-group/tracium/internal/logger"
	osinfo "github.com/ilexum-group/tracium/internal/os"
	"github.com/ilexum-group/tracium/internal/sender"
	"github.com/ilexum-group/tracium/pkg/models"
)

const (
	applicationName = "Tracium"
)

// version is set at build time via -ldflags
var version = "placeholder"

func main() {
	// Load configuration from CLI flags
	cfg := config.ParseFlags()

	// Validate configuration
	if err := config.ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Create custody chain entry
	custodyChain, err := models.NewCustodyChainEntry(applicationName, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create custody chain", map[string]string{"error": err.Error()})
		os.Exit(1)
	}

	// Initialize OS wrapper
	baseCollector := osinfo.New()

	// Wrap with logging collector to automatically log all method calls with timing
	osImpl := osinfo.NewLoggingCollector(baseCollector, custodyChain.LogCommand)

	// Get system information for initialization
	hostname, err := osImpl.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	currentUser, err := osImpl.GetCurrentUser()
	if err != nil {
		currentUser = "unknown"
	}

	processID := osImpl.GetProcessID()

	// Set hostname and user in custody chain
	custodyChain.SetAgentHostname(hostname)
	custodyChain.SetAgentUser(currentUser)

	// Initialize logger module (prioritize this over utils)
	if err := logger.InitDefaultLogger(applicationName, hostname, strconv.Itoa(processID)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.LogInfo("Configuration loaded", map[string]string{
		"server_url": cfg.ServerURL,
		"case_id":    cfg.CaseID,
	})
	logger.LogInfo("Starting Tracium agent", map[string]string{"version": version})

	// Collect system information using acquisition module
	data := collectData(custodyChain, osImpl)
	data.CaseID = cfg.CaseID

	logger.LogInfo("Data collection completed", map[string]string{})

	// Initialize sender module
	sender := sender.New(cfg.ServerURL, cfg.AgentToken)

	// Send data to server
	err = sender.SendData(data)
	if err != nil {
		logger.LogError("Failed to send data", map[string]string{"error": err.Error()})
		os.Exit(1)
	}

	logger.LogInfo("Data sent successfully", map[string]string{"status": "completed"})
}

func collectData(custodyChainEntry *models.CustodyChainEntry, collector osinfo.Collector) models.SystemData {
	// Create forensics collector if enabled
	forensicsCollector := forensics.New(collector, custodyChainEntry)

	// Create acquisition instance
	acq := acquisition.New(collector, custodyChainEntry, forensicsCollector)

	// Perform complete acquisition
	acquiredData := acq.Acquire()
	acquiredData.CustodyChain = custodyChainEntry

	// Collect forensics data if enabled
	logger.LogInfo("Collecting forensics data", map[string]string{})
	acquiredData.Forensics = forensicsCollector.Collect()

	logger.LogInfo("Forensics data collection completed", map[string]string{})

	return acquiredData
}
