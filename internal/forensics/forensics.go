// Package forensics provides forensic data collection capabilities
package forensics

import (
	"os"

	"github.com/ilexum-group/tracium/internal/artifactdetector"
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

// CollectForensicsData is a legacy function for backward compatibility.
// Use the New() constructor with dependency injection instead.
func CollectForensicsData() models.ForensicsData {
	collector := osinfo.New()
	forensics := models.ForensicsData{
		CollectionErrors: make([]string, 0),
	}

	forensics.Browser = collector.CollectBrowserArtifacts(&forensics.CollectionErrors)
	forensics.Communication = collector.CollectCommunicationArtifacts(&forensics.CollectionErrors)
	forensics.RecentFiles = collector.CollectRecentFiles(&forensics.CollectionErrors)
	forensics.CommandHistory = collector.CollectCommandHistory(&forensics.CollectionErrors)
	forensics.NetworkHistory = collector.CollectNetworkHistory(&forensics.CollectionErrors)
	forensics.SystemLogs = collector.CollectSystemLogs(&forensics.CollectionErrors)
	forensics.ScheduledTasks = collector.CollectScheduledTasks(&forensics.CollectionErrors)
	forensics.ActiveConnections = collector.CollectActiveConnections(&forensics.CollectionErrors)
	forensics.HostsFile = collector.CollectHostsFile(&forensics.CollectionErrors)
	forensics.SSHKeys = collector.CollectSSHKeys(&forensics.CollectionErrors)
	forensics.InstalledSoftware = collector.CollectInstalledSoftware(&forensics.CollectionErrors)
	forensics.EnvironmentVars = collector.CollectEnvironmentVariables(&forensics.CollectionErrors)
	forensics.RecentDownloads = collector.CollectRecentDownloads(&forensics.CollectionErrors)
	forensics.USBHistory = collector.CollectUSBHistory(&forensics.CollectionErrors)
	forensics.PrefetchFiles = collector.CollectPrefetchFiles(&forensics.CollectionErrors)
	forensics.RecycleBin = collector.CollectRecycleBin(&forensics.CollectionErrors)
	forensics.ClipboardContent = collector.CollectClipboard(&forensics.CollectionErrors)

	return forensics
}

// ClassifyBrowserArtifacts applies signature-based classification to browser artifacts
func ClassifyBrowserArtifacts(browser models.BrowserArtifacts) models.BrowserArtifacts {
	result := browser

	// Classify Chromium profiles
	for i := range result.ChromiumProfiles {
		result.ChromiumProfiles[i] = artifactdetector.ClassifyBrowserArtifact(result.ChromiumProfiles[i])
	}

	// Classify Chromium extensions
	for i := range result.ChromiumExtensions {
		result.ChromiumExtensions[i] = artifactdetector.ClassifyBrowserArtifact(result.ChromiumExtensions[i])
	}

	// Classify bookmarks
	for i := range result.Bookmarks {
		result.Bookmarks[i] = artifactdetector.ClassifyBrowserArtifact(result.Bookmarks[i])
	}

	// Classify cache
	for i := range result.Cache {
		result.Cache[i] = artifactdetector.ClassifyBrowserArtifact(result.Cache[i])
	}

	// Classify cookies
	for i := range result.Cookies {
		result.Cookies[i] = artifactdetector.ClassifyBrowserArtifact(result.Cookies[i])
	}

	// Classify downloads
	for i := range result.Downloads {
		result.Downloads[i] = artifactdetector.ClassifyBrowserArtifact(result.Downloads[i])
	}

	// Classify form autofill
	for i := range result.FormAutofill {
		result.FormAutofill[i] = artifactdetector.ClassifyBrowserArtifact(result.FormAutofill[i])
	}

	// Classify history
	for i := range result.History {
		result.History[i] = artifactdetector.ClassifyBrowserArtifact(result.History[i])
	}

	// Classify search history
	for i := range result.SearchHistory {
		result.SearchHistory[i] = artifactdetector.ClassifyBrowserArtifact(result.SearchHistory[i])
	}

	return result
}

// ClassifyCommunicationArtifacts applies signature-based classification to communication artifacts
func ClassifyCommunicationArtifacts(comm models.CommunicationArtifacts) models.CommunicationArtifacts {
	result := comm

	// Classify accounts
	for i := range result.Accounts {
		result.Accounts[i] = artifactdetector.ClassifyCommunicationArtifact(result.Accounts[i])
	}

	// Classify default emails
	for i := range result.Emails.Default {
		result.Emails.Default[i] = artifactdetector.ClassifyCommunicationArtifact(result.Emails.Default[i])
	}

	// Classify Gmail drafts
	for i := range result.Emails.Gmail.Drafts {
		result.Emails.Gmail.Drafts[i] = artifactdetector.ClassifyCommunicationArtifact(result.Emails.Gmail.Drafts[i])
	}

	// Classify Gmail sent
	for i := range result.Emails.Gmail.Sent {
		result.Emails.Gmail.Sent[i] = artifactdetector.ClassifyCommunicationArtifact(result.Emails.Gmail.Sent[i])
	}

	// Classify Gmail trash
	for i := range result.Emails.Gmail.Trash {
		result.Emails.Gmail.Trash[i] = artifactdetector.ClassifyCommunicationArtifact(result.Emails.Gmail.Trash[i])
	}

	return result
}

// DetectAndClassifyArtifact applies signature-based detection and classification to any forensic file
func DetectAndClassifyArtifact(file models.ForensicFile, artifactType string) models.ForensicFile {
	switch artifactType {
	case "browser":
		return artifactdetector.ClassifyBrowserArtifact(file)
	case "communication", "email":
		return artifactdetector.ClassifyCommunicationArtifact(file)
	default:
		// Try to detect based on file content
		data, err := os.ReadFile(file.Path)
		if err != nil {
			return file
		}

		if artifactdetector.IsSQLiteFile(data) {
			return artifactdetector.ClassifyBrowserArtifact(file)
		} else if artifactdetector.IsMBOXFile(data) || artifactdetector.IsPSTFile(data) {
			return artifactdetector.ClassifyCommunicationArtifact(file)
		}

		return file
	}
}
