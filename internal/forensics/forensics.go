// Package forensics provides forensic data collection capabilities
package forensics

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ilexum-group/tracium/internal/utils"
	"github.com/ilexum-group/tracium/pkg/models"
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

	// Collect system logs
	forensics.SystemLogs = collectSystemLogs(&forensics.CollectionErrors)

	// Collect scheduled tasks
	forensics.ScheduledTasks = collectScheduledTasks(&forensics.CollectionErrors)

	// Collect active network connections
	forensics.ActiveConnections = collectActiveConnections(&forensics.CollectionErrors)

	// Collect hosts file
	forensics.HostsFile = collectHostsFile(&forensics.CollectionErrors)

	// Collect SSH keys
	forensics.SSHKeys = collectSSHKeys(&forensics.CollectionErrors)

	// Collect installed software
	forensics.InstalledSoftware = collectInstalledSoftware(&forensics.CollectionErrors)

	// Collect environment variables
	forensics.EnvironmentVars = collectEnvironmentVariables(&forensics.CollectionErrors)

	// Collect recent downloads
	forensics.RecentDownloads = collectRecentDownloads(&forensics.CollectionErrors)

	// Collect USB device history
	forensics.USBHistory = collectUSBHistory(&forensics.CollectionErrors)

	// Collect prefetch files (Windows)
	forensics.PrefetchFiles = collectPrefetchFiles(&forensics.CollectionErrors)

	// Collect recycle bin
	forensics.RecycleBin = collectRecycleBin(&forensics.CollectionErrors)

	// Collect clipboard content
	forensics.ClipboardContent = collectClipboard(&forensics.CollectionErrors)

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
func collectRecentFiles(_ *[]string) []models.RecentFileEntry {
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
func collectCommandHistory(_ *[]string) []models.CommandEntry {
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
	//nolint:gosec // G304: path constructed from trusted environment variable
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
	//nolint:gosec // G304: path constructed from trusted UserHomeDir
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
	//nolint:gosec // G304: path constructed from trusted UserHomeDir
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
func collectNetworkHistory(_ *[]string) models.NetworkHistoryData {
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
	//nolint:gosec // G304: src is from trusted forensics collection sources
	sourceFile, err := os.Open(src)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		_ = sourceFile.Close()
	}()

	//nolint:gosec // G304: dst is controlled output path
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

// readFileWithLimit reads a file up to maxSize bytes and returns base64 encoded content
func readFileWithLimit(path string, maxSize int64) (string, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false, err
	}

	//nolint:gosec // G304: path is from trusted forensics collection sources
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = file.Close() }()

	truncated := info.Size() > maxSize
	readSize := info.Size()
	if truncated {
		readSize = maxSize
	}

	data := make([]byte, readSize)
	n, err := io.ReadFull(file, data)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", false, err
	}

	return base64.StdEncoding.EncodeToString(data[:n]), truncated, nil
}

// collectSystemLogs collects system log files
func collectSystemLogs(errors *[]string) []models.LogFile {
	logs := make([]models.LogFile, 0)
	maxLogSize := int64(1024 * 1024) // 1MB limit per log

	var logPaths []string

	switch runtime.GOOS {
	case "windows":
		// Windows Event Logs (export to temp files)
		eventLogs := []string{"System", "Security", "Application"}
		for _, logName := range eventLogs {
			tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s_log_%d.txt", logName, time.Now().UnixNano()))
			//nolint:gosec // G204: logName is from trusted list of system event logs
			cmd := exec.Command("powershell", "-Command",
				fmt.Sprintf("Get-EventLog -LogName %s -Newest 100 | Format-List | Out-File -FilePath '%s' -Encoding UTF8", logName, tempFile))
			if err := cmd.Run(); err == nil {
				logPaths = append(logPaths, tempFile)
			}
		}
	case "linux":
		possibleLogs := []string{
			"/var/log/syslog",
			"/var/log/auth.log",
			"/var/log/kern.log",
			"/var/log/messages",
			"/var/log/secure",
		}
		for _, path := range possibleLogs {
			if _, err := os.Stat(path); err == nil {
				logPaths = append(logPaths, path)
			}
		}
	case "darwin":
		possibleLogs := []string{
			"/var/log/system.log",
			"/var/log/install.log",
		}
		for _, path := range possibleLogs {
			if _, err := os.Stat(path); err == nil {
				logPaths = append(logPaths, path)
			}
		}
	}

	for _, logPath := range logPaths {
		info, err := os.Stat(logPath)
		if err != nil {
			continue
		}

		content, truncated, err := readFileWithLimit(logPath, maxLogSize)
		if err != nil {
			if errors != nil {
				*errors = append(*errors, fmt.Sprintf("failed to read log %s: %v", logPath, err))
			}
			continue
		}

		logs = append(logs, models.LogFile{
			Name:      filepath.Base(logPath),
			Path:      logPath,
			Size:      info.Size(),
			Content:   content,
			Truncated: truncated,
		})
	}

	utils.LogInfo("System logs collected", map[string]string{
		"count": fmt.Sprintf("%d", len(logs)),
	})

	return logs
}

// collectScheduledTasks collects scheduled tasks and cron jobs
func collectScheduledTasks(_ *[]string) []models.ScheduledTask {
	tasks := make([]models.ScheduledTask, 0)

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("schtasks", "/query", "/fo", "csv", "/v")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			scanner.Scan() // Skip header

			for scanner.Scan() {
				line := scanner.Text()
				fields := strings.Split(line, "\",\"")
				if len(fields) >= 3 {
					taskName := strings.Trim(fields[0], "\"")
					status := strings.Trim(fields[2], "\"")

					task := models.ScheduledTask{
						Name:    taskName,
						Enabled: strings.Contains(status, "Ready") || strings.Contains(status, "Running"),
						Source:  "windows_task",
					}

					if len(fields) > 8 {
						task.Command = strings.Trim(fields[8], "\"")
					}

					tasks = append(tasks, task)
				}
			}
		}
	case "linux", "darwin":
		// User crontab
		cmd := exec.Command("crontab", "-l")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				parts := strings.Fields(line)
				if len(parts) >= 6 {
					schedule := strings.Join(parts[0:5], " ")
					command := strings.Join(parts[5:], " ")

					tasks = append(tasks, models.ScheduledTask{
						Name:     command,
						Command:  command,
						Schedule: schedule,
						User:     os.Getenv("USER"),
						Enabled:  true,
						Source:   "crontab",
					})
				}
			}
		}

		// System cron
		cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"}
		for _, dir := range cronDirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if !entry.IsDir() {
					tasks = append(tasks, models.ScheduledTask{
						Name:    entry.Name(),
						Command: filepath.Join(dir, entry.Name()),
						Source:  "cron_dir",
						Enabled: true,
					})
				}
			}
		}

		// Systemd timers (Linux)
		if runtime.GOOS == "linux" {
			cmd := exec.Command("systemctl", "list-timers", "--all", "--no-pager", "--no-legend")
			output, err := cmd.Output()
			if err == nil {
				scanner := bufio.NewScanner(bytes.NewReader(output))
				for scanner.Scan() {
					fields := strings.Fields(scanner.Text())
					if len(fields) >= 2 {
						tasks = append(tasks, models.ScheduledTask{
							Name:    fields[len(fields)-2],
							Source:  "systemd_timer",
							Enabled: true,
						})
					}
				}
			}
		}
	}

	utils.LogInfo("Scheduled tasks collected", map[string]string{
		"count": fmt.Sprintf("%d", len(tasks)),
	})

	return tasks
}

// collectActiveConnections collects active network connections
func collectActiveConnections(errors *[]string) []models.NetworkConnection {
	connections := make([]models.NetworkConnection, 0)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("netstat", "-ano")
	case "linux", "darwin":
		cmd = exec.Command("netstat", "-antp")
	default:
		return connections
	}

	output, err := cmd.Output()
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to get connections: %v", err))
		}
		return connections
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		conn := models.NetworkConnection{
			Protocol: strings.ToUpper(fields[0]),
		}

		// Parse local address
		if strings.Contains(fields[1], ":") {
			parts := strings.Split(fields[1], ":")
			conn.LocalAddress = parts[0]
			if len(parts) > 1 {
				port, _ := strconv.Atoi(parts[len(parts)-1])
				conn.LocalPort = port
			}
		}

		// Parse remote address
		if len(fields) > 2 && strings.Contains(fields[2], ":") {
			parts := strings.Split(fields[2], ":")
			conn.RemoteAddress = parts[0]
			if len(parts) > 1 {
				port, _ := strconv.Atoi(parts[len(parts)-1])
				conn.RemotePort = port
			}
		}

		// Parse state
		if len(fields) > 3 {
			conn.State = fields[3]
		}

		// Parse PID (Windows has it at the end)
		if runtime.GOOS == "windows" && len(fields) > 4 {
			pid, _ := strconv.Atoi(fields[len(fields)-1])
			conn.PID = pid
		}

		connections = append(connections, conn)
	}

	utils.LogInfo("Active connections collected", map[string]string{
		"count": fmt.Sprintf("%d", len(connections)),
	})

	return connections
}

// collectHostsFile collects the hosts file
func collectHostsFile(errors *[]string) *models.ForensicFile {
	var hostsPath string

	switch runtime.GOOS {
	case "windows":
		hostsPath = filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	default:
		hostsPath = "/etc/hosts"
	}

	info, err := os.Stat(hostsPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("hosts file not found: %v", err))
		}
		return nil
	}

	content, _, err := readFileWithLimit(hostsPath, 1024*1024)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to read hosts file: %v", err))
		}
		return nil
	}

	//nolint:gosec // G304: hostsPath is trusted system file path
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to hash hosts file: %v", err))
		}
		return nil
	}

	hasher := sha256.New()
	hasher.Write(data)
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	utils.LogInfo("Hosts file collected", map[string]string{
		"path": hostsPath,
	})

	return &models.ForensicFile{
		Name:     "hosts",
		Path:     hostsPath,
		Size:     info.Size(),
		Hash:     hash,
		Category: "system_config",
		Data:     content,
	}
}

// collectSSHKeys collects SSH key information
func collectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	keys := make([]models.SSHKeyInfo, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return keys
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if _, err := os.Stat(sshDir); err != nil {
		return keys
	}

	keyFiles := []struct {
		name string
		typ  string
	}{
		{"authorized_keys", "authorized_keys"},
		{"known_hosts", "known_hosts"},
		{"id_rsa", "private_key"},
		{"id_rsa.pub", "public_key"},
		{"id_ed25519", "private_key"},
		{"id_ed25519.pub", "public_key"},
		{"id_ecdsa", "private_key"},
		{"id_ecdsa.pub", "public_key"},
	}

	for _, kf := range keyFiles {
		keyPath := filepath.Join(sshDir, kf.name)
		info, err := os.Stat(keyPath)
		if err != nil {
			continue
		}

		keyInfo := models.SSHKeyInfo{
			Path: keyPath,
			Type: kf.typ,
			Size: info.Size(),
		}

		// Read content for small files only (< 100KB)
		if info.Size() < 100*1024 {
			content, _, err := readFileWithLimit(keyPath, 100*1024)
			if err == nil {
				keyInfo.Content = content
			}
		}

		keys = append(keys, keyInfo)
	}

	utils.LogInfo("SSH keys collected", map[string]string{
		"count": fmt.Sprintf("%d", len(keys)),
	})

	return keys
}

// collectInstalledSoftware collects installed software information
func collectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)

	switch runtime.GOOS {
	case "windows":
		// Query Windows Registry for installed programs
		cmd := exec.Command("powershell", "-Command",
			"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object {$_.DisplayName -ne $null} | ConvertTo-Json")
		output, err := cmd.Output()
		if err == nil {
			outputStr := string(output)
			// Simple parsing (full JSON parser would be better)
			lines := strings.Split(outputStr, "\n")
			var current models.SoftwareInfo

			for _, line := range lines {
				line = strings.TrimSpace(line)
				switch {
				case strings.Contains(line, "\"DisplayName\""):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						current.Name = strings.Trim(strings.TrimSuffix(parts[1], ","), " \"")
					}
				case strings.Contains(line, "\"DisplayVersion\""):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						current.Version = strings.Trim(strings.TrimSuffix(parts[1], ","), " \"")
					}
				case strings.Contains(line, "\"Publisher\""):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						current.Publisher = strings.Trim(strings.TrimSuffix(parts[1], ","), " \"")
					}
				case strings.Contains(line, "\"InstallDate\""):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						current.InstallDate = strings.Trim(strings.TrimSuffix(parts[1], ","), " \"")
						current.Source = "registry"
						if current.Name != "" {
							software = append(software, current)
							current = models.SoftwareInfo{}
						}
					}
				case line == "}" && current.Name != "":
					current.Source = "registry"
					software = append(software, current)
					current = models.SoftwareInfo{}
				}
			}
		}
	case "linux":
		// Try different package managers
		packageManagers := []struct {
			cmd    string
			args   []string
			source string
		}{
			{"dpkg", []string{"-l"}, "dpkg"},
			{"rpm", []string{"-qa"}, "rpm"},
			{"pacman", []string{"-Q"}, "pacman"},
		}

		for _, pm := range packageManagers {
			//nolint:gosec // G204: pm.cmd and pm.args are from trusted package manager list
			cmd := exec.Command(pm.cmd, pm.args...)
			output, err := cmd.Output()
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				fields := strings.Fields(line)

				if len(fields) >= 2 {
					sw := models.SoftwareInfo{
						Name:    fields[0],
						Version: fields[1],
						Source:  pm.source,
					}

					// Skip header lines
					if !strings.HasPrefix(sw.Name, "ii") && !strings.HasPrefix(sw.Name, "Desired") {
						software = append(software, sw)
					}
				}
			}

			if len(software) > 0 {
				break // Found a working package manager
			}
		}
	case "darwin":
		// Use brew list
		cmd := exec.Command("brew", "list", "--versions")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					software = append(software, models.SoftwareInfo{
						Name:    parts[0],
						Version: parts[1],
						Source:  "brew",
					})
				}
			}
		}
	}

	// Limit to first 500 to avoid huge payloads
	if len(software) > 500 {
		software = software[:500]
	}

	utils.LogInfo("Installed software collected", map[string]string{
		"count": fmt.Sprintf("%d", len(software)),
	})

	return software
}

// collectEnvironmentVariables collects environment variables
func collectEnvironmentVariables(_ *[]string) map[string]string {
	envVars := make(map[string]string)

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}

	utils.LogInfo("Environment variables collected", map[string]string{
		"count": fmt.Sprintf("%d", len(envVars)),
	})

	return envVars
}

// collectRecentDownloads collects recently downloaded files
func collectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	downloads := make([]models.RecentFileEntry, 0)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return downloads
	}

	var downloadPaths []string
	switch runtime.GOOS {
	case "windows":
		downloadPaths = []string{
			filepath.Join(homeDir, "Downloads"),
			filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
		}
	default:
		downloadPaths = []string{
			filepath.Join(homeDir, "Downloads"),
		}
	}

	for _, downloadPath := range downloadPaths {
		entries, err := os.ReadDir(downloadPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Only files from last 30 days
			if time.Since(info.ModTime()) > 30*24*time.Hour {
				continue
			}

			fullPath := filepath.Join(downloadPath, entry.Name())
			downloads = append(downloads, models.RecentFileEntry{
				FilePath:     fullPath,
				FileName:     entry.Name(),
				AccessedTime: info.ModTime().Unix(),
				Source:       "downloads_folder",
			})
		}
	}

	utils.LogInfo("Recent downloads collected", map[string]string{
		"count": fmt.Sprintf("%d", len(downloads)),
	})

	return downloads
}

// collectUSBHistory collects USB device connection history
func collectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)

	switch runtime.GOOS {
	case "windows":
		// Query USB history from registry
		cmd := exec.Command("powershell", "-Command",
			"Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' | Select-Object FriendlyName,HardwareID,DeviceDesc | ConvertTo-Json")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			var current models.USBDevice

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "\"FriendlyName\"") || strings.Contains(line, "\"DeviceDesc\"") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						current.Description = strings.Trim(strings.TrimSuffix(parts[1], ","), " \"")
					}
				} else if strings.Contains(line, "\"HardwareID\"") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						current.DeviceID = strings.Trim(strings.TrimSuffix(parts[1], ","), " \"")
						if current.Description != "" {
							devices = append(devices, current)
							current = models.USBDevice{}
						}
					}
				}
			}
		}
	case "linux":
		// Check dmesg for USB connections
		cmd := exec.Command("dmesg")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "USB") && (strings.Contains(line, "New USB device") || strings.Contains(line, "Product:")) {
					devices = append(devices, models.USBDevice{
						Description: line,
						DeviceID:    "dmesg_entry",
					})
				}
			}
		}
	case "darwin":
		// Use system_profiler
		cmd := exec.Command("system_profiler", "SPUSBDataType")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			var currentDevice models.USBDevice

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				switch {
				case strings.Contains(line, "Product ID:"):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						currentDevice.ProductID = strings.TrimSpace(parts[1])
					}
				case strings.Contains(line, "Vendor ID:"):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						currentDevice.VendorID = strings.TrimSpace(parts[1])
					}
				case strings.Contains(line, "Serial Number:"):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						currentDevice.SerialNumber = strings.TrimSpace(parts[1])
						if currentDevice.ProductID != "" {
							devices = append(devices, currentDevice)
							currentDevice = models.USBDevice{}
						}
					}
				}
			}
		}
	}

	utils.LogInfo("USB history collected", map[string]string{
		"count": fmt.Sprintf("%d", len(devices)),
	})

	return devices
}

// collectPrefetchFiles collects Windows prefetch information
func collectPrefetchFiles(errors *[]string) []models.PrefetchInfo {
	prefetchInfo := make([]models.PrefetchInfo, 0)

	if runtime.GOOS != "windows" {
		return prefetchInfo
	}

	prefetchPath := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	entries, err := os.ReadDir(prefetchPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to read prefetch: %v", err))
		}
		return prefetchInfo
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pf") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Extract executable name from prefetch filename
		exeName := strings.TrimSuffix(entry.Name(), ".pf")
		parts := strings.Split(exeName, "-")
		if len(parts) > 0 {
			exeName = parts[0]
		}

		prefetchInfo = append(prefetchInfo, models.PrefetchInfo{
			FileName:    entry.Name(),
			Executable:  exeName,
			LastRunTime: info.ModTime().Unix(),
		})
	}

	utils.LogInfo("Prefetch files collected", map[string]string{
		"count": fmt.Sprintf("%d", len(prefetchInfo)),
	})

	return prefetchInfo
}

// collectRecycleBin collects recycle bin contents
func collectRecycleBin(errors *[]string) []models.DeletedFile {
	deletedFiles := make([]models.DeletedFile, 0)

	switch runtime.GOOS {
	case "windows":
		// Recycle bin path
		drives := []string{"C", "D", "E", "F"}
		for _, drive := range drives {
			recyclePath := fmt.Sprintf("%s:\\$Recycle.Bin", drive)

			// Need admin rights to enumerate all users' recycle bins
			err := filepath.Walk(recyclePath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil // Skip inaccessible
				}

				if !info.IsDir() && !strings.HasPrefix(info.Name(), "$I") {
					deletedFiles = append(deletedFiles, models.DeletedFile{
						DeletedPath:  path,
						FileName:     info.Name(),
						Size:         info.Size(),
						DeletedTime:  info.ModTime().Unix(),
						OriginalPath: "unknown",
					})
				}

				return nil
			})

			if err != nil && errors != nil {
				*errors = append(*errors, fmt.Sprintf("recycle bin walk error: %v", err))
			}
		}
	case "darwin":
		// macOS Trash
		homeDir, _ := os.UserHomeDir()
		trashPath := filepath.Join(homeDir, ".Trash")
		entries, err := os.ReadDir(trashPath)
		if err == nil {
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil {
					continue
				}

				deletedFiles = append(deletedFiles, models.DeletedFile{
					DeletedPath:  filepath.Join(trashPath, entry.Name()),
					FileName:     entry.Name(),
					Size:         info.Size(),
					DeletedTime:  info.ModTime().Unix(),
					OriginalPath: "unknown",
				})
			}
		}
	case "linux":
		// Linux Trash
		homeDir, _ := os.UserHomeDir()
		trashPath := filepath.Join(homeDir, ".local", "share", "Trash", "files")
		entries, err := os.ReadDir(trashPath)
		if err == nil {
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil {
					continue
				}

				deletedFiles = append(deletedFiles, models.DeletedFile{
					DeletedPath:  filepath.Join(trashPath, entry.Name()),
					FileName:     entry.Name(),
					Size:         info.Size(),
					DeletedTime:  info.ModTime().Unix(),
					OriginalPath: "unknown",
				})
			}
		}
	}

	utils.LogInfo("Recycle bin collected", map[string]string{
		"count": fmt.Sprintf("%d", len(deletedFiles)),
	})

	return deletedFiles
}

// collectClipboard collects current clipboard content
func collectClipboard(errors *[]string) string {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-Command", "Get-Clipboard")
	case "darwin":
		cmd = exec.Command("pbpaste")
	case "linux":
		// Try xclip first, then xsel
		cmd = exec.Command("xclip", "-selection", "clipboard", "-o")
		if _, err := exec.LookPath("xclip"); err != nil {
			cmd = exec.Command("xsel", "--clipboard", "--output")
		}
	default:
		return ""
	}

	output, err := cmd.Output()
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("clipboard access failed: %v", err))
		}
		return ""
	}

	content := string(output)

	// Limit clipboard content size
	if len(content) > 10000 {
		content = content[:10000] + "... [truncated]"
	}

	utils.LogInfo("Clipboard collected", map[string]string{
		"length": fmt.Sprintf("%d", len(content)),
	})

	return content
}
