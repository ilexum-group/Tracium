// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ilexum-group/tracium/pkg/models"
)

// Darwin implements Collector for macOS/Darwin systems
type Darwin struct {
	*Default
}

// NewDarwin creates a new Darwin instance
func NewDarwin() Collector {
	return NewDarwinWithDefault(NewDefault())
}

// NewDarwinWithDefault creates a new Darwin instance with a provided Default.
func NewDarwinWithDefault(def *Default) Collector {
	return &Darwin{
		Default: def,
	}
}

// GetCurrentUser returns the current user name
func (d *Darwin) GetCurrentUser() (string, error) {
	if !d.IsLive() {
		return "unknown", nil
	}
	currentUser, err := d.UserCurrent()
	if err != nil {
		return "", err
	}
	username := currentUser.Username
	return username, nil
}

// GetUptime returns the system uptime in seconds
func (d *Darwin) GetUptime() int64 {
	if !d.IsLive() {
		return 0
	}
	cmd := d.ExecCommand("sysctl", "-n", "kern.boottime")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse output like: { sec = 1234567890, usec = 0 }
	bootTimeStr := string(output)
	if strings.Contains(bootTimeStr, "sec") {
		parts := strings.Split(bootTimeStr, ",")
		if len(parts) > 0 {
			secPart := strings.TrimSpace(parts[0])
			secPart = strings.TrimPrefix(secPart, "{ sec = ")
			bootTimeSec, err := strconv.ParseInt(secPart, 10, 64)
			if err == nil {
				return time.Now().Unix() - bootTimeSec
			}
		}
	}

	return 0
}

// GetUsers returns the list of system users
func (d *Darwin) GetUsers() []string {
	var users []string

	file, err := d.OSOpen("/etc/passwd")
	if err != nil {
		if currentUser, err := d.UserCurrent(); err == nil {
			return []string{currentUser.Username}
		}
		return users
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, ":")
			if len(parts) > 0 && parts[0] != "" {
				users = append(users, parts[0])
			}
		}
	}

	users = append(users, collectDarwinUsersFromPlist(d)...)

	return users
}

// GetCPUInfo returns CPU information
func (d *Darwin) GetCPUInfo() models.CPUInfo {
	cpuInfo := models.CPUInfo{
		Cores: 0,
		Model: "Unknown",
	}
	if !d.IsLive() {
		return cpuInfo
	}

	cmd := d.ExecCommand("sysctl", "-n", "machdep.cpu.brand_string")
	output, err := cmd.Output()
	if err == nil {
		cpuInfo.Model = strings.TrimSpace(string(output))
	}

	cmd = d.ExecCommand("sysctl", "-n", "hw.ncpu")
	output, err = cmd.Output()
	if err == nil {
		cores, _ := strconv.Atoi(strings.TrimSpace(string(output)))
		cpuInfo.Cores = cores
	}

	return cpuInfo
}

// GetMemoryInfo returns memory information
func (d *Darwin) GetMemoryInfo() models.MemoryInfo {
	memInfo := models.MemoryInfo{}
	if !d.IsLive() {
		return memInfo
	}

	// Get total memory
	cmd := d.ExecCommand("sysctl", "-n", "hw.memsize")
	output, err := cmd.Output()
	if err == nil {
		total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		memInfo.Total = total
	}

	// Get used memory via vm_stat
	cmd = d.ExecCommand("vm_stat")
	output, err = cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		var pageSize uint64 = 4096
		var active, wired uint64

		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.Contains(line, "page size of"):
				parts := strings.Fields(line)
				if len(parts) > 7 {
					pageSize, _ = strconv.ParseUint(parts[7], 10, 64)
				}
			case strings.HasPrefix(line, "Pages active:"):
				parts := strings.Fields(line)
				if len(parts) > 2 {
					val := strings.TrimSuffix(parts[2], ".")
					active, _ = strconv.ParseUint(val, 10, 64)
				}
			case strings.HasPrefix(line, "Pages wired down:"):
				parts := strings.Fields(line)
				if len(parts) > 3 {
					val := strings.TrimSuffix(parts[3], ".")
					wired, _ = strconv.ParseUint(val, 10, 64)
				}
			}
		}
		memInfo.Used = (active + wired) * pageSize
	}

	return memInfo
}

// GetDiskInfo returns disk information
func (d *Darwin) GetDiskInfo() []models.DiskInfo {
	var disks []models.DiskInfo
	if !d.IsLive() {
		return disks
	}
	cmd := d.ExecCommand("df", "-k")
	output, err := cmd.Output()
	if err != nil {
		return disks
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 9 && strings.HasPrefix(fields[0], "/dev/") {
			total, _ := strconv.ParseUint(fields[1], 10, 64)
			used, _ := strconv.ParseUint(fields[2], 10, 64)
			mountPoint := fields[8]

			disks = append(disks, models.DiskInfo{
				Path:       mountPoint,
				Total:      total * 1024, // Convert KB to bytes
				Used:       used * 1024,
				FileSystem: fields[0],
			})
		}
	}

	return disks
}

// GetListeningPorts returns listening ports
//
//nolint:dupl // Similar netstat parsing, OS-specific differences in output format
func (d *Darwin) GetListeningPorts(seen map[int]bool) []int {
	var ports []int
	if !d.IsLive() {
		return ports
	}
	cmd := d.ExecCommand("netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return ports
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				localAddr := fields[3]
				parts := strings.Split(localAddr, ".")
				if len(parts) > 0 {
					portStr := parts[len(parts)-1]
					port, err := strconv.Atoi(portStr)
					if err == nil && !seen[port] {
						seen[port] = true
						ports = append(ports, port)
					}
				}
			}
		}
	}

	return ports
}

// GetProcesses returns running processes
func (d *Darwin) GetProcesses() []models.ProcessInfo {
	var processes []models.ProcessInfo
	if !d.IsLive() {
		return processes
	}
	cmd := d.ExecCommand("ps", "-eo", "pid,user,comm,%cpu,rss")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // Skip header

	count := 0
	for scanner.Scan() && count < 100 {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 {
			pid, _ := strconv.Atoi(fields[0])
			cpu, _ := strconv.ParseFloat(fields[3], 64)
			mem, _ := strconv.ParseUint(fields[4], 10, 64)

			processes = append(processes, models.ProcessInfo{
				PID:    pid,
				Name:   fields[2],
				User:   fields[1],
				CPU:    cpu,
				Memory: mem * 1024, // Convert KB to bytes
			})
			count++
		}
	}

	return processes
}

// GetServices returns system services
func (d *Darwin) GetServices() []models.ServiceInfo {
	var services []models.ServiceInfo
	if !d.IsLive() {
		return services
	}
	cmd := d.ExecCommand("launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // Skip header
	count := 0

	for scanner.Scan() && count < 50 {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			name := fields[2]
			status := "running"
			if fields[0] == "-" {
				status = "stopped"
			}

			services = append(services, models.ServiceInfo{
				Name:        name,
				Status:      status,
				Description: "",
			})
			count++
		}
	}

	return services
}

// Forensics methods implementation for Darwin (macOS)

// CollectBrowserArtifacts collects structured browser artifacts
func (d *Darwin) CollectBrowserArtifacts(errors *[]string) models.BrowserArtifacts {
	browser := models.BrowserArtifacts{
		ChromiumProfiles:   make([]models.ForensicFile, 0),
		ChromiumExtensions: make([]models.ForensicFile, 0),
		Bookmarks:          make([]models.ForensicFile, 0),
		Cache:              make([]models.ForensicFile, 0),
		Cookies:            make([]models.ForensicFile, 0),
		Downloads:          make([]models.ForensicFile, 0),
		FormAutofill:       make([]models.ForensicFile, 0),
		History:            make([]models.ForensicFile, 0),
		SearchHistory:      make([]models.ForensicFile, 0),
	}

	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		return browser
	}

	for _, homeDir := range homeDirs {
		// Chrome
		chromeBase := filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome")
		d.collectChromeProfileArtifactsDarwin(chromeBase, &browser, errors)

		// Safari
		safariBase := filepath.Join(homeDir, "Library", "Safari")
		d.collectSafariArtifacts(safariBase, &browser, errors)

		// Firefox
		firefoxProfiles := filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles")
		if profiles, err := filepath.Glob(filepath.Join(firefoxProfiles, "*.default*")); err == nil {
			for _, profile := range profiles {
				d.collectFirefoxArtifactsDarwin(profile, &browser, errors)
			}
		}

		// Edge
		edgeBase := filepath.Join(homeDir, "Library", "Application Support", "Microsoft Edge")
		d.collectChromeProfileArtifactsDarwin(edgeBase, &browser, errors)
	}

	return browser
}

// collectChromeProfileArtifactsDarwin collects Chrome/Chromium artifacts on macOS
func (d *Darwin) collectChromeProfileArtifactsDarwin(baseDir string, browser *models.BrowserArtifacts, errors *[]string) {
	if entries, err := d.OSReadDir(baseDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			profileDir := filepath.Join(baseDir, entry.Name())
			d.collectChromeProfileArtifacts(profileDir, browser, errors)
		}
	}

	// Default profile
	defaultProfile := filepath.Join(baseDir, "Default")
	d.collectChromeProfileArtifacts(defaultProfile, browser, errors)
}

// collectSafariArtifacts collects Safari browser artifacts
func (d *Darwin) collectSafariArtifacts(safariBase string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := d.OSStat(safariBase); err != nil {
		return
	}

	// History
	src := filepath.Join(safariBase, "History.db")
	if artifact, err := d.CopyFileArtifact(src, "safari_history", "safari"); err == nil {
		artifact.Category = "history"
		browser.History = append(browser.History, *artifact)
	} else if errors != nil && !strings.Contains(err.Error(), "artifact missing") {
		*errors = append(*errors, err.Error())
	}

	// Cookies (binary format)
	src = filepath.Join(safariBase, "Cookies.binarycookies")
	if artifact, err := d.CopyFileArtifact(src, "safari_cookies", "safari"); err == nil {
		artifact.Category = "cookies"
		browser.Cookies = append(browser.Cookies, *artifact)
	}

	// Bookmarks
	src = filepath.Join(safariBase, "Bookmarks.plist")
	if artifact, err := d.CopyFileArtifact(src, "safari_bookmarks", "safari"); err == nil {
		artifact.Category = "bookmarks"
		browser.Bookmarks = append(browser.Bookmarks, *artifact)
	}

	// Downloads
	src = filepath.Join(safariBase, "Downloads.plist")
	if artifact, err := d.CopyFileArtifact(src, "safari_downloads", "safari"); err == nil {
		artifact.Category = "downloads"
		browser.Downloads = append(browser.Downloads, *artifact)
	}

	// Form Autofill
	src = filepath.Join(safariBase, "Form Database")
	if _, err := d.OSStat(src); err == nil {
		if artifact, err := d.CopyFileArtifact(src, "safari_autofill", "safari"); err == nil {
			artifact.Category = "form_autofill"
			browser.FormAutofill = append(browser.FormAutofill, *artifact)
		}
	}

	// Cache
	cachePaths := []string{
		filepath.Join(safariBase, "Caches", "com.apple.Safari"),
	}
	for _, cachePath := range cachePaths {
		if _, err := d.OSStat(cachePath); err == nil {
			if artifact, err := d.CopyFileArtifact(cachePath, "safari_cache", "safari"); err == nil {
				artifact.Category = "cache"
				browser.Cache = append(browser.Cache, *artifact)
			}
		}
	}
}

// collectFirefoxArtifactsDarwin collects Firefox artifacts on macOS
func (d *Darwin) collectFirefoxArtifactsDarwin(profileDir string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := d.OSStat(profileDir); err != nil {
		return
	}

	// History (places.sqlite)
	src := filepath.Join(profileDir, "places.sqlite")
	if artifact, err := d.CopyFileArtifact(src, "firefox_places", "firefox"); err == nil {
		artifact.Category = "history"
		browser.History = append(browser.History, *artifact)
	} else if errors != nil && !strings.Contains(err.Error(), "artifact missing") {
		*errors = append(*errors, err.Error())
	}

	// Cookies
	src = filepath.Join(profileDir, "cookies.sqlite")
	if artifact, err := d.CopyFileArtifact(src, "firefox_cookies", "firefox"); err == nil {
		artifact.Category = "cookies"
		browser.Cookies = append(browser.Cookies, *artifact)
	}

	// Downloads
	src = filepath.Join(profileDir, "downloads.sqlite")
	if artifact, err := d.CopyFileArtifact(src, "firefox_downloads", "firefox"); err == nil {
		artifact.Category = "downloads"
		browser.Downloads = append(browser.Downloads, *artifact)
	}

	// Bookmarks
	src = filepath.Join(profileDir, "bookmarks.sqlite")
	if artifact, err := d.CopyFileArtifact(src, "firefox_bookmarks", "firefox"); err == nil {
		artifact.Category = "bookmarks"
		browser.Bookmarks = append(browser.Bookmarks, *artifact)
	}

	// Cache
	cacheDir := filepath.Join(profileDir, "cache2")
	if _, err := d.OSStat(cacheDir); err == nil {
		if artifact, err := d.CopyFileArtifact(cacheDir, "firefox_cache", "firefox"); err == nil {
			artifact.Category = "cache"
			browser.Cache = append(browser.Cache, *artifact)
		}
	}
}

// CollectCommunicationArtifacts collects communication artifacts on macOS
func (d *Darwin) CollectCommunicationArtifacts(errors *[]string) models.CommunicationArtifacts {
	comm := models.CommunicationArtifacts{
		Accounts: make([]models.ForensicFile, 0),
		Emails: models.EmailArtifacts{
			Default: make([]models.ForensicFile, 0),
			Gmail: models.GmailFolders{
				Drafts: make([]models.ForensicFile, 0),
				Sent:   make([]models.ForensicFile, 0),
				Trash:  make([]models.ForensicFile, 0),
			},
		},
	}

	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		return comm
	}

	for _, homeDir := range homeDirs {
		// Apple Mail
		mailDir := filepath.Join(homeDir, "Library", "Mail")
		d.collectAppleMailArtifacts(mailDir, &comm, errors)

		// Thunderbird
		thunderbirdPath := filepath.Join(homeDir, "Library", "Application Support", "Thunderbird")
		if profiles, err := filepath.Glob(filepath.Join(thunderbirdPath, "Profiles", "*.default*")); err == nil {
			for _, profile := range profiles {
				d.collectThunderbirdArtifacts(profile, &comm, errors)
			}
		}

		// Outlook
		outlookPath := filepath.Join(homeDir, "Library", "Group Containers", "UBF8T346G9.Office")
		if _, err := d.OSStat(outlookPath); err == nil {
			d.collectOutlookArtifacts(outlookPath, &comm, errors)
		}
	}

	return comm
}

// collectAppleMailArtifacts collects Apple Mail artifacts
func (d *Darwin) collectAppleMailArtifacts(mailDir string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := d.OSStat(mailDir); err != nil {
		return
	}

	// Envelope Index is the main database
	src := filepath.Join(mailDir, "V3", "Envelope Index")
	if artifact, err := d.CopyFileArtifact(src, "applemail_index", "apple-mail"); err == nil {
		artifact.Category = "email_default"
		comm.Emails.Default = append(comm.Emails.Default, *artifact)
	}

	// Also try older format
	src = filepath.Join(mailDir, "V2", "Envelope Index")
	if artifact, err := d.CopyFileArtifact(src, "applemail_index", "apple-mail"); err == nil {
		artifact.Category = "email_default"
		comm.Emails.Default = append(comm.Emails.Default, *artifact)
	}
}

// collectOutlookArtifacts collects Microsoft Outlook artifacts on macOS
func (d *Darwin) collectOutlookArtifacts(outlookPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	// Outlook database
	dataPath := filepath.Join(outlookPath, "Outlook", "Outlook.sqlite")
	if artifact, err := d.CopyFileArtifact(dataPath, "outlook_data", "outlook"); err == nil {
		artifact.Category = "email_default"
		comm.Emails.Default = append(comm.Emails.Default, *artifact)
	}
}

// CollectRecentFiles collects recently accessed files
func (d *Darwin) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		return files
	}

	for _, homeDir := range homeDirs {
		recentItemsPath := filepath.Join(homeDir, "Library", "Application Support", "com.apple.sharedfilelist")
		if entries, err := d.OSReadDir(recentItemsPath); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					files = append(files, models.RecentFileEntry{
						FilePath:     filepath.Join(recentItemsPath, entry.Name()),
						FileName:     entry.Name(),
						AccessedTime: time.Now().Unix(),
						Source:       "sharedfilelist",
					})
				}
			}
		}
	}

	return files
}

// CollectCommandHistory collects shell command history
//
//nolint:dupl // Similar Unix shell history collection, platform-specific paths
func (d *Darwin) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		return commands
	}

	for _, homeDir := range homeDirs {
		// Bash history
		historyPath := filepath.Join(homeDir, ".bash_history")
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := d.OSReadFile(historyPath); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					commands = append(commands, models.CommandEntry{
						Shell:   "bash",
						Command: line,
						LineNum: i + 1,
					})
				}
			}
		}

		// Zsh history (default on macOS Catalina+)
		historyPath = filepath.Join(homeDir, ".zsh_history")
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := d.OSReadFile(historyPath); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					if strings.Contains(line, ";") {
						if parts := strings.SplitN(line, ";", 2); len(parts) == 2 {
							line = parts[1]
						}
					}
					commands = append(commands, models.CommandEntry{
						Shell:   "zsh",
						Command: line,
						LineNum: i + 1,
					})
				}
			}
		}
	}

	return commands
}

// CollectNetworkHistory collects network connection history
func (d *Darwin) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	return models.NetworkHistoryData{
		ARPCache: d.CollectARPCacheUnix(),
		DNSCache: make([]models.DNSEntry, 0), // macOS doesn't expose DNS cache easily
	}
}

// CollectSystemLogs collects system log files
func (d *Darwin) CollectSystemLogs(errors *[]string) []models.LogFile {
	logs := make([]models.LogFile, 0)
	maxLogSize := int64(1024 * 1024)

	logPaths := []string{
		"/var/log/system.log",
		"/var/log/install.log",
	}

	for _, logPath := range logPaths {
		info, err := d.OSStat(logPath)
		if err != nil {
			continue
		}

		content, truncated, err := d.ReadFileWithLimit(logPath, maxLogSize)
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

	logs = append(logs, collectDarwinUnifiedLogs(d)...)

	return logs
}

// CollectScheduledTasks collects scheduled tasks (launchd jobs)
func (d *Darwin) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	tasks := make([]models.ScheduledTask, 0)

	// User launchd agents
	homeDirs, _ := d.OSUserHomeDirs()
	agentDirs := []string{
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
	}
	for _, homeDir := range homeDirs {
		agentDirs = append(agentDirs, filepath.Join(homeDir, "Library", "LaunchAgents"))
	}

	for _, dir := range agentDirs {
		if entries, err := d.OSReadDir(dir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".plist" {
					plistPath := filepath.Join(dir, entry.Name())
					if task := parseLaunchdPlist(d, plistPath, dir); task != nil {
						tasks = append(tasks, *task)
					}
				}
			}
		}
	}

	// User crontab
	if d.IsLive() {
		if output, err := d.ExecCommand("crontab", "-l").Output(); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				if parts := strings.Fields(line); len(parts) >= 6 {
					tasks = append(tasks, models.ScheduledTask{
						Name:     strings.Join(parts[5:], " "),
						Command:  strings.Join(parts[5:], " "),
						Schedule: strings.Join(parts[0:5], " "),
						Enabled:  true,
						Source:   "crontab",
					})
				}
			}
		}
	}

	return tasks
}

// CollectActiveConnections collects active network connections
func (d *Darwin) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	return d.CollectNetstatConnections("darwin", errors)
}

// CollectHostsFile collects the hosts file
func (d *Darwin) CollectHostsFile(errors *[]string) *models.ForensicFile {
	return d.CollectHostsFileCommon("/etc/hosts", errors)
}

// CollectSSHKeys collects SSH key information
func (d *Darwin) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return d.CollectSSHKeysCommon()
}

// CollectInstalledSoftware collects installed software information
func (d *Darwin) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)
	software = append(software, collectDarwinApplications(d)...)
	software = append(software, collectDarwinReceipts(d)...)

	if d.IsLive() {
		if output, err := d.ExecCommand("brew", "list", "--versions").Output(); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				if fields := strings.Fields(scanner.Text()); len(fields) >= 2 {
					software = append(software, models.SoftwareInfo{
						Name:    fields[0],
						Version: fields[1],
						Source:  "homebrew",
					})
				}
			}
		}
	}

	return software
}

// CollectEnvironmentVariables collects environment variables
func (d *Darwin) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return d.CollectEnvironmentVariablesCommon()
}

// CollectRecentDownloads collects recently downloaded files
func (d *Darwin) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return d.CollectDownloadsCommon(nil)
}

// CollectUSBHistory collects USB device connection history
func (d *Darwin) CollectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)
	if !d.IsLive() {
		return devices
	}

	if output, err := d.ExecCommand("system_profiler", "SPUSBDataType").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Product ID:") || strings.Contains(line, "Vendor ID:") {
				devices = append(devices, models.USBDevice{
					Description: strings.TrimSpace(line),
					DeviceID:    "system_profiler_entry",
				})
			}
		}
	}

	return devices
}

// CollectPrefetchFiles collects Windows prefetch information (not applicable for macOS)
func (d *Darwin) CollectPrefetchFiles(_ *[]string) []models.PrefetchInfo {
	return make([]models.PrefetchInfo, 0)
}

// CollectRecycleBin collects trash contents
func (d *Darwin) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	deletedFiles := make([]models.DeletedFile, 0)
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		return deletedFiles
	}

	for _, homeDir := range homeDirs {
		trashPath := filepath.Join(homeDir, ".Trash")
		if entries, err := d.OSReadDir(trashPath); err == nil {
			for _, entry := range entries {
				if info, err := entry.Info(); err == nil {
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
	}

	return deletedFiles
}

// CollectClipboard collects current clipboard content
func (d *Darwin) CollectClipboard(errors *[]string) string {
	if !d.IsLive() {
		return ""
	}
	output, err := d.ExecCommand("pbpaste").Output()
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("clipboard access failed: %v", err))
		}
		return ""
	}

	content := string(output)
	if len(content) > 10000 {
		content = content[:10000] + "... [truncated]"
	}

	return content
}

// CollectFilesystemTree collects filesystem tree for macOS
func (d *Darwin) CollectFilesystemTree() models.FilesystemTree {
	if d.IsLive() {
		return d.collectFilesystemTreeLive()
	}
	return d.collectFilesystemTreeImage()
}

func (d *Darwin) collectFilesystemTreeLive() models.FilesystemTree {
	cmd := d.ExecCommand("sh", "-c", "find / -xdev -print0 | xargs -0 stat -f '%N|%HT|%z|%Su|%Sg|%Lp|%m'")
	output, err := cmd.Output()
	if err != nil {
		return models.FilesystemTree{Nodes: d.collectTreeWithTreeCommand()}
	}
	return models.FilesystemTree{Nodes: parseBSDStatOutput(output)}
}
