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

// Linux implements Collector for Linux systems
type Linux struct {
	*Default
}

// NewLinux creates a new Linux instance
func NewLinux() Collector {
	return &Linux{
		Default: NewDefault(),
	}
}

// GetCurrentUser returns the current user name
func (l *Linux) GetCurrentUser() (string, error) {
	currentUser, err := l.UserCurrent()
	if err != nil {
		return "", err
	}
	return currentUser.Username, nil
}

// GetUptime returns the system uptime in seconds
func (l *Linux) GetUptime() int64 {
	data, err := l.OSReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	parts := strings.Fields(string(data))
	if len(parts) > 0 {
		uptimeFloat, err := strconv.ParseFloat(parts[0], 64)
		if err == nil {
			return int64(uptimeFloat)
		}
	}
	return 0
}

// GetUsers returns the list of system users
func (l *Linux) GetUsers() []string {
	var users []string

	file, err := l.OSOpen("/etc/passwd")
	if err != nil {
		// Fallback to current user
		if currentUser, err := l.UserCurrent(); err == nil {
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

	return users
}

// GetCPUInfo returns CPU information
func (l *Linux) GetCPUInfo() models.CPUInfo {
	cpuInfo := models.CPUInfo{
		Cores: 0,
		Model: "Unknown",
	}

	data, err := l.OSReadFile("/proc/cpuinfo")
	if err != nil {
		return cpuInfo
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	processorCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "processor") {
			processorCount++
		} else if strings.HasPrefix(line, "model name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				cpuInfo.Model = strings.TrimSpace(parts[1])
			}
		}
	}

	cpuInfo.Cores = processorCount
	return cpuInfo
}

// GetMemoryInfo returns memory information
func (l *Linux) GetMemoryInfo() models.MemoryInfo {
	memInfo := models.MemoryInfo{}

	data, err := l.OSReadFile("/proc/meminfo")
	if err != nil {
		return memInfo
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				memInfo.Total = val * 1024 // Convert KB to bytes
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				available, _ := strconv.ParseUint(parts[1], 10, 64)
				memInfo.Used = memInfo.Total - (available * 1024)
			}
		}
	}

	return memInfo
}

// GetDiskInfo returns disk information
func (l *Linux) GetDiskInfo() []models.DiskInfo {
	var disks []models.DiskInfo
	data, err := l.OSReadFile("/proc/mounts")
	if err != nil {
		return disks
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		device := parts[0]
		mountPoint := parts[1]
		fsType := parts[2]

		// Skip non-physical filesystems
		if strings.HasPrefix(device, "/dev/") && !seen[mountPoint] {
			seen[mountPoint] = true

			//nolint:gosec // G204: mountPoint is validated from /proc/mounts
			cmd := l.ExecCommand("df", "-B1", mountPoint)
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\n")
				if len(lines) > 1 {
					fields := strings.Fields(lines[1])
					if len(fields) >= 4 {
						total, _ := strconv.ParseUint(fields[1], 10, 64)
						used, _ := strconv.ParseUint(fields[2], 10, 64)

						disks = append(disks, models.DiskInfo{
							Path:       mountPoint,
							Total:      total,
							Used:       used,
							FileSystem: fsType,
						})
					}
				}
			}
		}
	}

	return disks
}

// GetListeningPorts returns listening ports
func (l *Linux) GetListeningPorts(seen map[int]bool) []int {
	var ports []int

	// Parse /proc/net/tcp and /proc/net/tcp6
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		//nolint:gosec // G304: /proc files are trusted system paths
		data, err := l.OSReadFile(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}

			// State 0A = LISTEN
			state := fields[3]
			if state == "0A" {
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) == 2 {
					portHex := parts[1]
					port, err := strconv.ParseInt(portHex, 16, 64)
					if err == nil && !seen[int(port)] {
						seen[int(port)] = true
						ports = append(ports, int(port))
					}
				}
			}
		}
	}

	// Also check UDP
	for _, file := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		//nolint:gosec // G304: /proc files are trusted system paths
		data, err := l.OSReadFile(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}

			state := fields[3]
			if state == "07" {
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) == 2 {
					portHex := parts[1]
					port, err := strconv.ParseInt(portHex, 16, 64)
					if err == nil && !seen[int(port)] {
						seen[int(port)] = true
						ports = append(ports, int(port))
					}
				}
			}
		}
	}

	return ports
}

// GetProcesses returns running processes
func (l *Linux) GetProcesses() []models.ProcessInfo {
	var processes []models.ProcessInfo
	entries, err := l.OSReadDir("/proc")
	if err != nil {
		return processes
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		procInfo := models.ProcessInfo{PID: pid}

		// Get command name
		cmdline, err := l.OSReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && len(cmdline) > 0 {
			parts := bytes.Split(cmdline, []byte{0})
			if len(parts) > 0 {
				procInfo.Name = filepath.Base(string(parts[0]))
			}
		}

		// Get status info
		status, err := l.OSReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(status))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						uid := fields[1]
						if u, err := l.UserLookupID(uid); err == nil {
							procInfo.User = u.Username
						} else {
							procInfo.User = uid
						}
					}
				} else if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						mem, _ := strconv.ParseUint(fields[1], 10, 64)
						procInfo.Memory = mem * 1024
					}
				}
			}
		}

		// Get CPU usage
		stat, err := l.OSReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err == nil {
			fields := strings.Fields(string(stat))
			if len(fields) > 13 {
				utime, _ := strconv.ParseUint(fields[13], 10, 64)
				stime, _ := strconv.ParseUint(fields[14], 10, 64)
				totalTime := float64(utime + stime)
				procInfo.CPU = totalTime / 100.0
			}
		}

		if procInfo.Name != "" {
			processes = append(processes, procInfo)
			if len(processes) >= 100 {
				break
			}
		}
	}

	return processes
}

// GetServices returns system services
func (l *Linux) GetServices() []models.ServiceInfo {
	var services []models.ServiceInfo

	// Try systemctl first
	cmd := l.ExecCommand("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		count := 0

		for scanner.Scan() && count < 50 {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				name := strings.TrimSuffix(fields[0], ".service")
				status := "unknown"
				switch fields[2] {
				case "active":
					status = "running"
				case "inactive", "failed":
					status = "stopped"
				}

				description := strings.Join(fields[4:], " ")

				services = append(services, models.ServiceInfo{
					Name:        name,
					Status:      status,
					Description: description,
				})
				count++
			}
		}
		return services
	}

	// Fallback to service --status-all
	cmd = l.ExecCommand("service", "--status-all")
	output, err = cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	count := 0

	for scanner.Scan() && count < 50 {
		line := scanner.Text()
		status := "unknown"
		name := ""

		switch {
		case strings.Contains(line, "[+]"):
			status = "running"
			name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "[+]"))
		case strings.Contains(line, "[-]"):
			status = "stopped"
			name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "[-]"))
		case strings.Contains(line, "[?]"):
			status = "unknown"
			name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "[?]"))
		}

		if name != "" {
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

// Forensics methods implementation for Linux

// CollectBrowserDBFiles collects browser database files
//
//nolint:dupl // Similar implementation for Linux, slight differences in browser paths
func (l *Linux) CollectBrowserDBFiles(errors *[]string) []models.ForensicFile {
	files := make([]models.ForensicFile, 0)
	homeDir, _ := l.OSUserHomeDir()

	// Chrome
	chromeBase := filepath.Join(homeDir, ".config", "google-chrome", "Default")
	for _, name := range []string{"History", "Cookies"} {
		src := filepath.Join(chromeBase, name)
		if artifact, err := l.CopyFileArtifact(src, "chrome_"+strings.ToLower(name), "chrome"); err == nil {
			files = append(files, *artifact)
		} else if errors != nil {
			*errors = append(*errors, err.Error())
		}
	}

	// Firefox
	firefoxProfiles := filepath.Join(homeDir, ".mozilla", "firefox")
	if profiles, err := filepath.Glob(filepath.Join(firefoxProfiles, "*.default*")); err == nil {
		for _, profile := range profiles {
			for _, name := range []string{"places.sqlite", "cookies.sqlite"} {
				src := filepath.Join(profile, name)
				if artifact, err := l.CopyFileArtifact(src, "firefox_"+strings.TrimSuffix(name, ".sqlite"), "firefox"); err == nil {
					files = append(files, *artifact)
				} else if errors != nil {
					*errors = append(*errors, err.Error())
				}
			}
		}
	}

	return files
}

// CollectRecentFiles collects recently accessed files
func (l *Linux) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)
	homeDir, err := l.OSUserHomeDir()
	if err != nil {
		return files
	}

	recentPath := filepath.Join(homeDir, ".local", "share", "recently-used.xbel")
	if _, err := l.OSStat(recentPath); err == nil {
		files = append(files, models.RecentFileEntry{
			FilePath:     recentPath,
			FileName:     "recently-used.xbel",
			AccessedTime: time.Now().Unix(),
			Source:       "xbel",
		})
	}

	return files
}

// CollectCommandHistory collects shell command history
//
//nolint:dupl // Similar Unix shell history collection, platform-specific behavior
func (l *Linux) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)
	homeDir, err := l.OSUserHomeDir()
	if err != nil {
		return commands
	}

	// Bash history
	historyPath := filepath.Join(homeDir, ".bash_history")
	//nolint:gosec // G304: path constructed from trusted UserHomeDir
	if content, err := l.OSReadFile(historyPath); err == nil {
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

	// Zsh history
	historyPath = filepath.Join(homeDir, ".zsh_history")
	//nolint:gosec // G304: path constructed from trusted UserHomeDir
	if content, err := l.OSReadFile(historyPath); err == nil {
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

	return commands
}

// CollectNetworkHistory collects network connection history
func (l *Linux) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	return models.NetworkHistoryData{
		ARPCache: l.CollectARPCacheUnix(),
		DNSCache: make([]models.DNSEntry, 0), // Linux doesn't have standard DNS cache
	}
}

// CollectSystemLogs collects system log files
func (l *Linux) CollectSystemLogs(errors *[]string) []models.LogFile {
	logs := make([]models.LogFile, 0)
	maxLogSize := int64(1024 * 1024)

	logPaths := []string{
		"/var/log/syslog",
		"/var/log/auth.log",
		"/var/log/kern.log",
		"/var/log/messages",
		"/var/log/secure",
	}

	for _, logPath := range logPaths {
		info, err := l.OSStat(logPath)
		if err != nil {
			continue
		}

		content, truncated, err := l.ReadFileWithLimit(logPath, maxLogSize)
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

	return logs
}

// CollectScheduledTasks collects scheduled tasks and cron jobs
func (l *Linux) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	tasks := make([]models.ScheduledTask, 0)

	// User crontab
	if output, err := l.ExecCommand("crontab", "-l").Output(); err == nil {
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
					User:     l.OSGetenv("USER"),
					Enabled:  true,
					Source:   "crontab",
				})
			}
		}
	}

	// System cron directories
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"} {
		if entries, err := l.OSReadDir(dir); err == nil {
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
	}

	// Systemd timers
	if output, err := l.ExecCommand("systemctl", "list-timers", "--all", "--no-pager", "--no-legend").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			if fields := strings.Fields(scanner.Text()); len(fields) >= 2 {
				tasks = append(tasks, models.ScheduledTask{
					Name:    fields[len(fields)-2],
					Source:  "systemd_timer",
					Enabled: true,
				})
			}
		}
	}

	return tasks
}

// CollectActiveConnections collects active network connections
func (l *Linux) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	return l.CollectNetstatConnections("linux", errors)
}

// CollectHostsFile collects the hosts file
func (l *Linux) CollectHostsFile(errors *[]string) *models.ForensicFile {
	return l.CollectHostsFileCommon("/etc/hosts", errors)
}

// CollectSSHKeys collects SSH key information
func (l *Linux) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return l.CollectSSHKeysCommon()
}

// CollectInstalledSoftware collects installed software information
func (l *Linux) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)

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
		if output, err := l.ExecCommand(pm.cmd, pm.args...).Output(); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				if fields := strings.Fields(scanner.Text()); len(fields) >= 2 {
					sw := models.SoftwareInfo{
						Name:    fields[0],
						Version: fields[1],
						Source:  pm.source,
					}
					if !strings.HasPrefix(sw.Name, "ii") && !strings.HasPrefix(sw.Name, "Desired") {
						software = append(software, sw)
					}
				}
			}
			if len(software) > 0 {
				break
			}
		}
	}

	if len(software) > 500 {
		software = software[:500]
	}

	return software
}

// CollectEnvironmentVariables collects environment variables
func (l *Linux) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return l.CollectEnvironmentVariablesCommon()
}

// CollectRecentDownloads collects recently downloaded files
func (l *Linux) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return l.CollectDownloadsCommon(nil)
}

// CollectUSBHistory collects USB device connection history
func (l *Linux) CollectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)

	if output, err := l.ExecCommand("dmesg").Output(); err == nil {
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

	return devices
}

// CollectPrefetchFiles collects Windows prefetch information (not applicable for Linux)
func (l *Linux) CollectPrefetchFiles(_ *[]string) []models.PrefetchInfo {
	return make([]models.PrefetchInfo, 0)
}

// CollectRecycleBin collects recycle bin contents
func (l *Linux) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	deletedFiles := make([]models.DeletedFile, 0)
	homeDir, _ := l.OSUserHomeDir()
	trashPath := filepath.Join(homeDir, ".local", "share", "Trash", "files")

	if entries, err := l.OSReadDir(trashPath); err == nil {
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

	return deletedFiles
}

// CollectClipboard collects current clipboard content
func (l *Linux) CollectClipboard(errors *[]string) string {
	cmd := l.ExecCommand("xclip", "-selection", "clipboard", "-o")
	if _, err := l.ExecCommand("which", "xclip").Output(); err != nil {
		cmd = l.ExecCommand("xsel", "--clipboard", "--output")
	}

	output, err := cmd.Output()
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
