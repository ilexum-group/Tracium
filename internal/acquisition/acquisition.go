// Package acquisition provides functions to collect system, hardware, network, and security information.
package acquisition

import (
	"fmt"

	"github.com/ilexum-group/tracium/internal/forensics"
	osinfo "github.com/ilexum-group/tracium/internal/os"
	"github.com/ilexum-group/tracium/pkg/models"
)

// Acquisition manages system information collection with dependency injection
type Acquisition struct {
	collector    osinfo.Collector
	custodyChain *models.CustodyChainEntry
	forensics    *forensics.Forensics
}

// New creates a new Acquisition instance with the provided dependencies
func New(collector osinfo.Collector, custodyChain *models.CustodyChainEntry, forensicsCollector *forensics.Forensics) *Acquisition {
	return &Acquisition{
		collector:    collector,
		custodyChain: custodyChain,
		forensics:    forensicsCollector,
	}
}

// Acquire performs complete system data acquisition and returns all collected information
func (a *Acquisition) Acquire() models.SystemData {
	a.custodyChain.LogInfo("Acquire", "Starting complete system acquisition process")

	data := models.SystemData{
		System:   a.CollectSystemInfo(),
		Hardware: a.CollectHardwareInfo(),
		Network:  a.CollectNetworkInfo(),
		Security: a.CollectSecurityInfo(),
		Forensics: func() models.ForensicsData {
			if a.forensics != nil {
				return a.forensics.Collect()
			}
			return models.ForensicsData{CollectionErrors: make([]string, 0)}
		}(),
		Tree: a.collector.CollectFilesystemTree(),
	}

	a.custodyChain.LogInfo("Acquire", "Complete system acquisition process finished successfully")
	return data
}

// CollectSystemInfo collects basic system information
func (a *Acquisition) CollectSystemInfo() models.SystemInfo {
	a.custodyChain.LogInfo("CollectSystemInfo", "Starting system information collection")
	fmt.Printf("[acquisition] CollectSystemInfo start\n")

	hostname, _ := a.collector.Hostname()

	systemInfo := models.SystemInfo{
		OS:           a.collector.OSName(),
		Hostname:     hostname,
		Architecture: a.collector.Architecture(),
		Uptime:       a.collector.GetUptime(),
		Users:        a.collector.GetUsers(),
	}

	a.custodyChain.LogInfo("CollectSystemInfo", "System information collection completed successfully")
	fmt.Printf("[acquisition] CollectSystemInfo done\n")
	return systemInfo
}

// CollectHardwareInfo collects hardware information
func (a *Acquisition) CollectHardwareInfo() models.HardwareInfo {
	a.custodyChain.LogInfo("CollectHardwareInfo", "Starting hardware information collection")
	fmt.Printf("[acquisition] CollectHardwareInfo start\n")

	hardwareInfo := models.HardwareInfo{
		CPU:    a.collector.GetCPUInfo(),
		Memory: a.collector.GetMemoryInfo(),
		Disk:   a.collector.GetDiskInfo(),
	}

	a.custodyChain.LogInfo("CollectHardwareInfo", "Hardware information collection completed successfully")
	fmt.Printf("[acquisition] CollectHardwareInfo done\n")
	return hardwareInfo
}

// CollectNetworkInfo collects network information
func (a *Acquisition) CollectNetworkInfo() models.NetworkInfo {
	a.custodyChain.LogInfo("CollectNetworkInfo", "Starting network information collection")
	fmt.Printf("[acquisition] CollectNetworkInfo start\n")

	networkInfo := models.NetworkInfo{
		Interfaces:     a.collector.GetInterfaces(),
		ListeningPorts: a.collector.GetListeningPorts(make(map[int]bool)),
	}

	a.custodyChain.LogInfo("CollectNetworkInfo", "Network information collection completed successfully")
	fmt.Printf("[acquisition] CollectNetworkInfo done\n")
	return networkInfo
}

// CollectSecurityInfo collects security-related information
func (a *Acquisition) CollectSecurityInfo() models.SecurityInfo {
	a.custodyChain.LogInfo("CollectSecurityInfo", "Starting security information collection")
	fmt.Printf("[acquisition] CollectSecurityInfo start\n")

	securityInfo := models.SecurityInfo{
		Processes: a.collector.GetProcesses(),
		Services:  a.collector.GetServices(),
	}

	a.custodyChain.LogInfo("CollectSecurityInfo", "Security information collection completed successfully")
	fmt.Printf("[acquisition] CollectSecurityInfo done\n")
	return securityInfo
}
