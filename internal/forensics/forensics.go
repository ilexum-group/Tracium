// Package forensics provides forensic data collection capabilities
package forensics

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tracium/internal/models"
	"github.com/tracium/internal/utils"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for browser databases
)

// CollectForensicsData collects all forensic artifacts
func CollectForensicsData() models.ForensicsData {
	forensics := models.ForensicsData{
		CollectionErrors: make([]string, 0),
	}

	// Collect browser history
	forensics.BrowserHistory = collectBrowserHistory(&forensics.CollectionErrors)

	// Collect cookies
	forensics.Cookies = collectCookies(&forensics.CollectionErrors)

	// Collect recent files
	forensics.RecentFiles = collectRecentFiles(&forensics.CollectionErrors)

	// Collect command history
	forensics.CommandHistory = collectCommandHistory(&forensics.CollectionErrors)

	// Collect downloads
	forensics.Downloads = collectDownloads(&forensics.CollectionErrors)

	// Collect network history
	forensics.NetworkHistory = collectNetworkHistory(&forensics.CollectionErrors)

	return forensics
}

// collectBrowserHistory collects browser history from Chrome, Firefox, Edge
func collectBrowserHistory(errors *[]string) []models.BrowserHistoryEntry {
	history := make([]models.BrowserHistoryEntry, 0)

	// Chrome
	chromeHistory := collectChromeHistory()
	history = append(history, chromeHistory...)

	// Firefox
	firefoxHistory := collectFirefoxHistory()
	history = append(history, firefoxHistory...)

	// Edge
	edgeHistory := collectEdgeHistory()
	history = append(history, edgeHistory...)

	utils.LogInfo("Browser history collected", map[string]string{
		"entries": fmt.Sprintf("%d", len(history)),
	})

	return history
}

// collectChromeHistory collects Chrome browser history
func collectChromeHistory() []models.BrowserHistoryEntry {
	entries := make([]models.BrowserHistoryEntry, 0)

	var historyPath string
	switch runtime.GOOS {
	case "windows":
		historyPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "History")
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		historyPath = filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default", "History")
	case "linux":
		homeDir, _ := os.UserHomeDir()
		historyPath = filepath.Join(homeDir, ".config", "google-chrome", "Default", "History")
	default:
		return entries
	}

	// Copy database to temp location (Chrome locks the file)
	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("chrome_history_%d.db", time.Now().Unix()))
	if err := copyFile(historyPath, tempPath); err != nil {
		utils.LogDebug("Chrome history not accessible", map[string]string{"error": err.Error()})
		return entries
	}
	defer func() {
		if err := os.Remove(tempPath); err != nil {
			utils.LogDebug("Failed to remove temp Chrome history", map[string]string{"error": err.Error()})
		}
	}()

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return entries
	}
	defer func() {
		if err := db.Close(); err != nil {
			utils.LogDebug("Failed to close Chrome history db", map[string]string{"error": err.Error()})
		}
	}()

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_time, typed_count FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
	if err != nil {
		return entries
	}
	defer func() {
		if err := rows.Close(); err != nil {
			utils.LogDebug("Failed to close Chrome history rows", map[string]string{"error": err.Error()})
		}
	}()

	for rows.Next() {
		var url, title string
		var visitCount, typedCount int
		var lastVisitTime int64

		if err := rows.Scan(&url, &title, &visitCount, &lastVisitTime, &typedCount); err != nil {
			continue
		}

		// Chrome stores time as microseconds since 1601-01-01, convert to Unix
		unixTime := chromeTimeToUnix(lastVisitTime)

		entries = append(entries, models.BrowserHistoryEntry{
			Browser:       "chrome",
			URL:           url,
			Title:         title,
			VisitCount:    visitCount,
			LastVisitTime: unixTime,
			Typed:         typedCount > 0,
		})
	}

	return entries
}

// collectFirefoxHistory collects Firefox browser history
func collectFirefoxHistory() []models.BrowserHistoryEntry {
	entries := make([]models.BrowserHistoryEntry, 0)

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
		return entries
	}

	// Find profile directories
	profiles, err := filepath.Glob(filepath.Join(profilesDir, "*.default*"))
	if err != nil || len(profiles) == 0 {
		return entries
	}

	for _, profile := range profiles {
		placesPath := filepath.Join(profile, "places.sqlite")

		// Copy to temp
		tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("firefox_places_%d.db", time.Now().Unix()))
		if err := copyFile(placesPath, tempPath); err != nil {
			continue
		}
		defer func(path string) {
			if err := os.Remove(path); err != nil {
				utils.LogDebug("Failed to remove temp Firefox places", map[string]string{"error": err.Error()})
			}
		}(tempPath)

		db, err := sql.Open("sqlite3", tempPath)
		if err != nil {
			continue
		}

		rows, err := db.Query(`
			SELECT url, title, visit_count, last_visit_date 
			FROM moz_places 
			WHERE last_visit_date IS NOT NULL 
			ORDER BY last_visit_date DESC 
			LIMIT 1000
		`)
		if err != nil {
			_ = db.Close()
			continue
		}

		for rows.Next() {
			var url, title string
			var visitCount int
			var lastVisitDate int64

			if err := rows.Scan(&url, &title, &visitCount, &lastVisitDate); err != nil {
				continue
			}

			// Firefox stores time as microseconds since Unix epoch
			unixTime := lastVisitDate / 1000000

			entries = append(entries, models.BrowserHistoryEntry{
				Browser:       "firefox",
				URL:           url,
				Title:         title,
				VisitCount:    visitCount,
				LastVisitTime: unixTime,
			})
		}

		_ = rows.Close()
		_ = db.Close()
	}

	return entries
}

// collectEdgeHistory collects Edge browser history
func collectEdgeHistory() []models.BrowserHistoryEntry {
	entries := make([]models.BrowserHistoryEntry, 0)

	if runtime.GOOS != "windows" {
		return entries
	}

	historyPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default", "History")

	// Copy to temp
	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("edge_history_%d.db", time.Now().Unix()))
	if err := copyFile(historyPath, tempPath); err != nil {
		return entries
	}
	defer func() {
		if err := os.Remove(tempPath); err != nil {
			utils.LogDebug("Failed to remove temp Edge history", map[string]string{"error": err.Error()})
		}
	}()

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return entries
	}
	defer func() {
		if err := db.Close(); err != nil {
			utils.LogDebug("Failed to close Edge history db", map[string]string{"error": err.Error()})
		}
	}()

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
	if err != nil {
		return entries
	}
	defer func() {
		if err := rows.Close(); err != nil {
			utils.LogDebug("Failed to close Edge history rows", map[string]string{"error": err.Error()})
		}
	}()

	for rows.Next() {
		var url, title string
		var visitCount int
		var lastVisitTime int64

		if err := rows.Scan(&url, &title, &visitCount, &lastVisitTime); err != nil {
			continue
		}

		unixTime := chromeTimeToUnix(lastVisitTime)

		entries = append(entries, models.BrowserHistoryEntry{
			Browser:       "edge",
			URL:           url,
			Title:         title,
			VisitCount:    visitCount,
			LastVisitTime: unixTime,
		})
	}

	return entries
}

// collectCookies collects browser cookies
func collectCookies(errors *[]string) []models.CookieEntry {
	cookies := make([]models.CookieEntry, 0)

	// Note: Cookie values are often encrypted, especially in Chrome
	// This collects metadata but may not decrypt values

	utils.LogInfo("Cookie collection completed", map[string]string{
		"entries": fmt.Sprintf("%d", len(cookies)),
	})

	return cookies
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

// collectDownloads collects download history
func collectDownloads(errors *[]string) []models.DownloadEntry {
	downloads := make([]models.DownloadEntry, 0)

	// Collect from Chrome
	downloads = append(downloads, collectChromeDownloads()...)

	// Collect from Firefox
	downloads = append(downloads, collectFirefoxDownloads()...)

	utils.LogInfo("Downloads collected", map[string]string{
		"entries": fmt.Sprintf("%d", len(downloads)),
	})

	return downloads
}

// collectChromeDownloads collects Chrome download history
func collectChromeDownloads() []models.DownloadEntry {
	downloads := make([]models.DownloadEntry, 0)

	var historyPath string
	switch runtime.GOOS {
	case "windows":
		historyPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "History")
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		historyPath = filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default", "History")
	case "linux":
		homeDir, _ := os.UserHomeDir()
		historyPath = filepath.Join(homeDir, ".config", "google-chrome", "Default", "History")
	default:
		return downloads
	}

	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("chrome_downloads_%d.db", time.Now().Unix()))
	if err := copyFile(historyPath, tempPath); err != nil {
		return downloads
	}
	defer func() {
		if err := os.Remove(tempPath); err != nil {
			utils.LogDebug("Failed to remove temp Chrome downloads", map[string]string{"error": err.Error()})
		}
	}()

	db, err := sql.Open("sqlite3", tempPath)
	if err != nil {
		return downloads
	}
	defer func() {
		if err := db.Close(); err != nil {
			utils.LogDebug("Failed to close Chrome downloads db", map[string]string{"error": err.Error()})
		}
	}()

	rows, err := db.Query(`
		SELECT target_path, tab_url, start_time, end_time, total_bytes, state, danger_type, mime_type 
		FROM downloads 
		ORDER BY start_time DESC 
		LIMIT 500
	`)
	if err != nil {
		return downloads
	}
	defer func() {
		if err := rows.Close(); err != nil {
			utils.LogDebug("Failed to close Chrome downloads rows", map[string]string{"error": err.Error()})
		}
	}()

	for rows.Next() {
		var targetPath, tabURL, dangerType, mimeType string
		var startTime, endTime, totalBytes int64
		var state int

		if err := rows.Scan(&targetPath, &tabURL, &startTime, &endTime, &totalBytes, &state, &dangerType, &mimeType); err != nil {
			continue
		}

		stateStr := "unknown"
		switch state {
		case 0:
			stateStr = "in_progress"
		case 1:
			stateStr = "complete"
		case 2:
			stateStr = "cancelled"
		case 3:
			stateStr = "interrupted"
		}

		downloads = append(downloads, models.DownloadEntry{
			Browser:    "chrome",
			FilePath:   targetPath,
			URL:        tabURL,
			StartTime:  chromeTimeToUnix(startTime),
			EndTime:    chromeTimeToUnix(endTime),
			BytesTotal: totalBytes,
			State:      stateStr,
			DangerType: dangerType,
			MimeType:   mimeType,
		})
	}

	return downloads
}

// collectFirefoxDownloads collects Firefox download history
func collectFirefoxDownloads() []models.DownloadEntry {
	downloads := make([]models.DownloadEntry, 0)

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
		return downloads
	}

	profiles, err := filepath.Glob(filepath.Join(profilesDir, "*.default*"))
	if err != nil || len(profiles) == 0 {
		return downloads
	}

	for _, profile := range profiles {
		placesPath := filepath.Join(profile, "places.sqlite")

		tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("firefox_downloads_%d.db", time.Now().Unix()))
		if err := copyFile(placesPath, tempPath); err != nil {
			continue
		}
		defer func(path string) {
			if err := os.Remove(path); err != nil {
				utils.LogDebug("Failed to remove temp Firefox downloads", map[string]string{"error": err.Error()})
			}
		}(tempPath)

		db, err := sql.Open("sqlite3", tempPath)
		if err != nil {
			continue
		}

		rows, err := db.Query(`
			SELECT content FROM moz_annos 
			WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name = 'downloads/metaData')
			LIMIT 500
		`)
		if err != nil {
			_ = db.Close()
			continue
		}

		for rows.Next() {
			var content string
			if err := rows.Scan(&content); err != nil {
				continue
			}

			// Parse JSON metadata
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(content), &metadata); err != nil {
				continue
			}

			filePath, _ := metadata["targetPath"].(string)
			url, _ := metadata["source"].(string)

			downloads = append(downloads, models.DownloadEntry{
				Browser:  "firefox",
				FilePath: filePath,
				URL:      url,
				State:    "unknown",
			})
		}

		_ = rows.Close()
		_ = db.Close()
	}

	return downloads
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

// Helper functions

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := sourceFile.Close(); err != nil {
			utils.LogDebug("Failed to close source file", map[string]string{"error": err.Error()})
		}
	}()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if err := destFile.Close(); err != nil {
			utils.LogDebug("Failed to close dest file", map[string]string{"error": err.Error()})
		}
	}()

	_, err = sourceFile.WriteTo(destFile)
	return err
}

// chromeTimeToUnix converts Chrome's timestamp format to Unix timestamp
// Chrome stores time as microseconds since 1601-01-01
func chromeTimeToUnix(chromeTime int64) int64 {
	if chromeTime == 0 {
		return 0
	}
	// Number of microseconds between 1601-01-01 and 1970-01-01
	const epochDiff = 11644473600000000
	return (chromeTime - epochDiff) / 1000000
}
