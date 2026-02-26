// Package forensics provides forensic data collection capabilities
package forensics

import (
	osinfo "github.com/ilexum-group/tracium/internal/os"
	"github.com/ilexum-group/tracium/pkg/models"
)

// Forensics manages forensic data collection with dependency injection
type Forensics struct {
	collector    osinfo.Collector
	custodyChain *models.CustodyChainEntry
}

// New creates a new Forensics instance with the provided dependencies
func New(collector osinfo.Collector, custodyChain *models.CustodyChainEntry) *Forensics {
	return &Forensics{
		collector:    collector,
		custodyChain: custodyChain,
	}
}

// Collect performs complete forensics data collection
func (f *Forensics) Collect() models.ForensicsData {
	f.custodyChain.LogInfo("Forensics", "Starting forensics data collection")

	forensics := models.ForensicsData{
		CollectionErrors: make([]string, 0),
	}

	f.custodyChain.LogInfo("Forensics", "Collecting browser artifacts")
	forensics.Browser = f.collector.CollectBrowserArtifacts(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting communication artifacts")
	forensics.Communication = f.collector.CollectCommunicationArtifacts(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting recent files")
	forensics.RecentFiles = f.collector.CollectRecentFiles(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting command history")
	forensics.CommandHistory = f.collector.CollectCommandHistory(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting network history")
	forensics.NetworkHistory = f.collector.CollectNetworkHistory(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting system logs")
	forensics.SystemLogs = f.collector.CollectSystemLogs(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting scheduled tasks")
	forensics.ScheduledTasks = f.collector.CollectScheduledTasks(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting active connections")
	forensics.ActiveConnections = f.collector.CollectActiveConnections(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting hosts file")
	forensics.HostsFile = f.collector.CollectHostsFile(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting SSH keys")
	forensics.SSHKeys = f.collector.CollectSSHKeys(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting installed software")
	forensics.InstalledSoftware = f.collector.CollectInstalledSoftware(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting environment variables")
	forensics.EnvironmentVars = f.collector.CollectEnvironmentVariables(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting recent downloads")
	forensics.RecentDownloads = f.collector.CollectRecentDownloads(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting USB history")
	forensics.USBHistory = f.collector.CollectUSBHistory(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting prefetch files")
	forensics.PrefetchFiles = f.collector.CollectPrefetchFiles(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting recycle bin")
	forensics.RecycleBin = f.collector.CollectRecycleBin(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Collecting clipboard content")
	forensics.ClipboardContent = f.collector.CollectClipboard(&forensics.CollectionErrors)

	f.custodyChain.LogInfo("Forensics", "Forensics data collection completed successfully")
	return forensics
}
