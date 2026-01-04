// Package forensics provides forensic data collection capabilities
package forensics

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tracium/internal/models"
	"github.com/tracium/internal/utils"
)

// CollectForensicsData collects all forensic artifacts
func CollectForensicsData() models.ForensicsData {
	forensics := models.ForensicsData{
		CollectionErrors: make([]string, 0),
	}

	// Collect browser database files (server will query)
	forensics.BrowserDBFiles = collectBrowserDBFiles(&forensics.CollectionErrors)

	// Collect recent files
	forensics.RecentFiles = collectRecentFiles(&forensics.CollectionErrors)

	// Collect command history
	forensics.CommandHistory = collectCommandHistory(&forensics.CollectionErrors)

	// Collect network history
	forensics.NetworkHistory = collectNetworkHistory(&forensics.CollectionErrors)

	return forensics
}

// collectBrowserDBFiles copies browser database files so the server can query them
func collectBrowserDBFiles(errors *[]string) []models.ForensicFile {
	files := make([]models.ForensicFile, 0)

	// Chrome
	files = append(files, copyChromeDBs(errors)...)

	// Firefox
	files = append(files, copyFirefoxDBs(errors)...)

	// Edge (Windows only)
	files = append(files, copyEdgeDBs(errors)...)

	utils.LogInfo("Browser DBs collected", map[string]string{
		"count": fmt.Sprintf("%d", len(files)),
	})

	return files
}

// collectRecentFiles collects recently accessed files
func collectRecentFiles(errors *[]string) []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)

	switch runtime.GOOS {
	case "windows":
		files = append(files, collectWindowsRecentFiles()...)
	case "linux":
		files = append(files, collectLinuxRecentFiles()...)
	case "darwin":
		files = append(files, collectMacOSRecentFiles()...)
	}

	utils.LogInfo("Recent files collected", map[string]string{
		"entries": fmt.Sprintf("%d", len(files)),
	})

	return files
}

// collectWindowsRecentFiles collects Windows recent files
func collectWindowsRecentFiles() []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)

	recentPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	entries, err := os.ReadDir(recentPath)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		fullPath := filepath.Join(recentPath, entry.Name())
		files = append(files, models.RecentFileEntry{
			FilePath:     fullPath,
			FileName:     entry.Name(),
			AccessedTime: info.ModTime().Unix(),
			Source:       "windows_recent",
		})
	}

	return files
}

// collectLinuxRecentFiles collects Linux recent files
func collectLinuxRecentFiles() []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return files
	}

	recentPath := filepath.Join(homeDir, ".local", "share", "recently-used.xbel")
	// This is an XML file, would need XML parsing
	// Simplified implementation - just check if exists
	if _, err := os.Stat(recentPath); err == nil {
		files = append(files, models.RecentFileEntry{
			FilePath:     recentPath,
			FileName:     "recently-used.xbel",
			AccessedTime: time.Now().Unix(),
			Source:       "xbel",
		})
	}

	return files
}

// collectMacOSRecentFiles collects macOS recent files
func collectMacOSRecentFiles() []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)

	// macOS stores recent items in various locations
	// This is a simplified implementation

	return files
}

// collectCommandHistory collects shell command history
func collectCommandHistory(errors *[]string) []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)

	switch runtime.GOOS {
	case "windows":
		commands = append(commands, collectPowerShellHistory()...)
	case "linux", "darwin":
		commands = append(commands, collectBashHistory()...)
		commands = append(commands, collectZshHistory()...)
	}

	utils.LogInfo("Command history collected", map[string]string{
		"entries": fmt.Sprintf("%d", len(commands)),
	})

	return commands
}

// collectPowerShellHistory collects PowerShell history
func collectPowerShellHistory() []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)

	historyPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
	content, err := os.ReadFile(historyPath)
	if err != nil {
		return commands
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		commands = append(commands, models.CommandEntry{
			Shell:   "powershell",
			Command: line,
			LineNum: i + 1,
		})
	}

	return commands
}

// collectBashHistory collects bash history
func collectBashHistory() []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return commands
	}

	historyPath := filepath.Join(homeDir, ".bash_history")
	content, err := os.ReadFile(historyPath)
	if err != nil {
		return commands
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		commands = append(commands, models.CommandEntry{
			Shell:   "bash",
			Command: line,
			LineNum: i + 1,
		})
	}

	return commands
}

// collectZshHistory collects zsh history
func collectZshHistory() []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return commands
	}

	historyPath := filepath.Join(homeDir, ".zsh_history")
	content, err := os.ReadFile(historyPath)
	if err != nil {
		return commands
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Zsh history format: : <timestamp>:<duration>;<command>
		if strings.Contains(line, ";") {
			parts := strings.SplitN(line, ";", 2)
			if len(parts) == 2 {
				line = parts[1]
			}
		}

		commands = append(commands, models.CommandEntry{
			Shell:   "zsh",
			Command: line,
			LineNum: i + 1,
		})
	}

	return commands
}

// collectNetworkHistory collects network connection history
func collectNetworkHistory(errors *[]string) models.NetworkHistoryData {
	networkHistory := models.NetworkHistoryData{
		ARPCache: make([]models.ARPEntry, 0),
		DNSCache: make([]models.DNSEntry, 0),
	}

	// Collect ARP cache
	networkHistory.ARPCache = collectARPCache()

	// Collect DNS cache
	networkHistory.DNSCache = collectDNSCache()

	utils.LogInfo("Network history collected", map[string]string{
		"arp_entries": fmt.Sprintf("%d", len(networkHistory.ARPCache)),
		"dns_entries": fmt.Sprintf("%d", len(networkHistory.DNSCache)),
	})

	return networkHistory
}

// collectARPCache collects ARP cache entries
func collectARPCache() []models.ARPEntry {
	entries := make([]models.ARPEntry, 0)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a")
	case "linux", "darwin":
		cmd = exec.Command("arp", "-n")
	default:
		return entries
	}

	output, err := cmd.Output()
	if err != nil {
		return entries
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Interface") || strings.HasPrefix(line, "Address") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		entry := models.ARPEntry{
			Type: "dynamic",
		}

		if runtime.GOOS == "windows" {
			if len(fields) >= 3 {
				entry.IPAddress = fields[0]
				entry.MACAddress = fields[1]
				if len(fields) > 3 {
					entry.Type = strings.ToLower(fields[2])
				}
			}
		} else {
			entry.IPAddress = fields[0]
			if len(fields) > 2 {
				entry.MACAddress = fields[2]
			}
		}

		entries = append(entries, entry)
	}

	return entries
}

// collectDNSCache collects DNS cache entries
func collectDNSCache() []models.DNSEntry {
	entries := make([]models.DNSEntry, 0)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ipconfig", "/displaydns")
	case "darwin":
		cmd = exec.Command("dscacheutil", "-cachedump", "-entries", "host")
	case "linux":
		// Linux doesn't have a standard DNS cache command
		return entries
	default:
		return entries
	}

	output, err := cmd.Output()
	if err != nil {
		return entries
	}

	if runtime.GOOS == "windows" {
		lines := strings.Split(string(output), "\n")
		var currentHost string
		var currentIPs []string

		for _, line := range lines {
			line = strings.TrimSpace(line)

			if strings.Contains(line, "Record Name") {
				if currentHost != "" && len(currentIPs) > 0 {
					entries = append(entries, models.DNSEntry{
						Hostname:   currentHost,
						IPAddress:  currentIPs,
						RecordType: "A",
					})
				}
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					currentHost = strings.TrimSpace(parts[1])
					currentIPs = make([]string, 0)
				}
			} else if strings.Contains(line, "A (Host) Record") || strings.Contains(line, "AAAA Record") {
				// Next line will have IP
			} else if strings.Contains(line, ":") && currentHost != "" {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					ip := strings.TrimSpace(parts[1])
					if ip != "" && ip != "---" {
						currentIPs = append(currentIPs, ip)
					}
				}
			}
		}

		if currentHost != "" && len(currentIPs) > 0 {
			entries = append(entries, models.DNSEntry{
				Hostname:   currentHost,
				IPAddress:  currentIPs,
				RecordType: "A",
			})
		}
	}

	return entries
}

// copyChromeDBs copies Chrome database files (History, Cookies) without querying them
func copyChromeDBs(errors *[]string) []models.ForensicFile {
	artifacts := make([]models.ForensicFile, 0)

	var baseDir string
	switch runtime.GOOS {
	case "windows":
		baseDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default")
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		baseDir = filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default")
	case "linux":
		homeDir, _ := os.UserHomeDir()
		baseDir = filepath.Join(homeDir, ".config", "google-chrome", "Default")
	default:
		return artifacts
	}

	files := []string{"History", "Cookies"}
	for _, name := range files {
		src := filepath.Join(baseDir, name)
		artifact, err := copyArtifact(src, fmt.Sprintf("chrome_%s", strings.ToLower(name)), "chrome")
		if err != nil {
			if errors != nil {
				*errors = append(*errors, err.Error())
			}
			continue
		}
		if artifact != nil {
			artifacts = append(artifacts, *artifact)
		}
	}

	return artifacts
}

// copyEdgeDBs copies Edge database files without querying them (Windows only)
func copyEdgeDBs(errors *[]string) []models.ForensicFile {
	artifacts := make([]models.ForensicFile, 0)
	if runtime.GOOS != "windows" {
		return artifacts
	}

	baseDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default")
	files := []string{"History", "Cookies"}
	for _, name := range files {
		src := filepath.Join(baseDir, name)
		artifact, err := copyArtifact(src, fmt.Sprintf("edge_%s", strings.ToLower(name)), "edge")
		if err != nil {
			if errors != nil {
				*errors = append(*errors, err.Error())
			}
			continue
		}
		if artifact != nil {
			artifacts = append(artifacts, *artifact)
		}
	}

	return artifacts
}

// copyFirefoxDBs copies Firefox database files (places.sqlite, cookies.sqlite)
func copyFirefoxDBs(errors *[]string) []models.ForensicFile {
	artifacts := make([]models.ForensicFile, 0)

	var profilesDir string
	switch runtime.GOOS {
	case "windows":
		profilesDir = filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		profilesDir = filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles")
	case "linux":
		homeDir, _ := os.UserHomeDir()
		profilesDir = filepath.Join(homeDir, ".mozilla", "firefox")
	default:
		return artifacts
	}

	profiles, err := filepath.Glob(filepath.Join(profilesDir, "*.default*"))
	if err != nil || len(profiles) == 0 {
		return artifacts
	}

	for _, profile := range profiles {
		files := []string{"places.sqlite", "cookies.sqlite"}
		for _, name := range files {
			src := filepath.Join(profile, name)
			artifact, err := copyArtifact(src, fmt.Sprintf("firefox_%s", strings.TrimSuffix(name, ".sqlite")), "firefox")
			if err != nil {
				if errors != nil {
					*errors = append(*errors, err.Error())
				}
				continue
			}
			if artifact != nil {
				artifacts = append(artifacts, *artifact)
			}
		}
	}

	return artifacts
}

// copyArtifact copies a file if it exists and returns its metadata
func copyArtifact(src, prefix, browser string) (*models.ForensicFile, error) {
	if _, err := os.Stat(src); err != nil {
		return nil, fmt.Errorf("artifact missing: %s", src)
	}

	dest := filepath.Join(os.TempDir(), fmt.Sprintf("%s_%d.db", prefix, time.Now().UnixNano()))
	size, hash, err := copyFileWithHash(src, dest)
	if err != nil {
		return nil, fmt.Errorf("copy failed for %s: %w", src, err)
	}

	return &models.ForensicFile{
		Name:     filepath.Base(src),
		Path:     dest,
		Size:     size,
		Hash:     hash,
		Category: "browser_db",
		Browser:  browser,
	}, nil
}

// Helper functions

// copyFileWithHash copies a file to dst computing SHA-256 hash and returns size and hash
func copyFileWithHash(src, dst string) (int64, string, error) {
	sourceFile, err := os.Open(src)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		_ = sourceFile.Close()
	}()

	destFile, err := os.Create(dst)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		_ = destFile.Close()
	}()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destFile, hasher), sourceFile)
	if err != nil {
		return 0, "", err
	}

	return written, fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
