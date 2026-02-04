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

	"github.com/ilexum-group/tracium/pkg/models"
)

// FreeBSD implements Collector for FreeBSD systems
type FreeBSD struct {
	*Default
}

// NewFreeBSD creates a new FreeBSD instance
func NewFreeBSD() Collector {
	return &FreeBSD{
		Default: NewDefault(),
	}
}

// GetCurrentUser returns the current user name
func (f *FreeBSD) GetCurrentUser() (string, error) {
	currentUser, err := f.UserCurrent()
	username := ""
	if err == nil {
		username = currentUser.Username
	}
	return username, err
}

// GetUptime returns the system uptime in seconds
func (f *FreeBSD) GetUptime() int64 {
	return getBSDUptime(f)
}

// GetUsers returns the list of system users
func (f *FreeBSD) GetUsers() []string {
	return getUnixUsers(f)
}

// GetCPUInfo returns CPU information
func (f *FreeBSD) GetCPUInfo() models.CPUInfo {
	return getBSDCPUInfo(f)
}

// GetMemoryInfo returns memory information
func (f *FreeBSD) GetMemoryInfo() models.MemoryInfo {
	return getBSDMemoryInfo(f)
}

// GetDiskInfo returns disk information
func (f *FreeBSD) GetDiskInfo() []models.DiskInfo {
	return getBSDDiskInfo(f)
}

// GetListeningPorts returns listening ports
func (f *FreeBSD) GetListeningPorts(seen map[int]bool) []int {
	return getUnixListeningPorts(f, seen)
}

// GetProcesses returns running processes
func (f *FreeBSD) GetProcesses() []models.ProcessInfo {
	return getBSDProcesses(f)
}

// GetServices returns system services
func (f *FreeBSD) GetServices() []models.ServiceInfo {
	var services []models.ServiceInfo
	cmd := f.ExecCommand("service", "-e")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	count := 0

	for scanner.Scan() && count < 50 {
		servicePath := strings.TrimSpace(scanner.Text())
		name := filepath.Base(servicePath)

		services = append(services, models.ServiceInfo{
			Name:        name,
			Status:      "running",
			Description: "",
		})
		count++
	}

	return services
}

// OpenBSD implements Collector for OpenBSD systems
type OpenBSD struct {
	*Default
}

// NewOpenBSD creates a new OpenBSD instance
func NewOpenBSD() Collector {
	return &OpenBSD{
		Default: NewDefault(),
	}
}

// GetCurrentUser returns the current user name
func (o *OpenBSD) GetCurrentUser() (string, error) {
	currentUser, err := o.UserCurrent()
	if err != nil {
		return "", err
	}
	username := currentUser.Username
	return username, err
}

// GetUptime returns the system uptime in seconds
func (o *OpenBSD) GetUptime() int64 {
	return getBSDUptime(o)
}

// GetUsers returns the list of system users
func (o *OpenBSD) GetUsers() []string {
	return getUnixUsers(o)
}

// GetCPUInfo returns CPU information
func (o *OpenBSD) GetCPUInfo() models.CPUInfo {
	return getBSDCPUInfo(o)
}

// GetMemoryInfo returns memory information
func (o *OpenBSD) GetMemoryInfo() models.MemoryInfo {
	return getBSDMemoryInfo(o)
}

// GetDiskInfo returns disk information
func (o *OpenBSD) GetDiskInfo() []models.DiskInfo {
	return getBSDDiskInfo(o)
}

// GetListeningPorts returns listening ports
func (o *OpenBSD) GetListeningPorts(seen map[int]bool) []int {
	return getUnixListeningPorts(o, seen)
}

// GetProcesses returns running processes
func (o *OpenBSD) GetProcesses() []models.ProcessInfo {
	return getBSDProcesses(o)
}

// GetServices returns system services
func (o *OpenBSD) GetServices() []models.ServiceInfo {
	var services []models.ServiceInfo
	cmd := o.ExecCommand("rcctl", "ls", "started")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	count := 0

	for scanner.Scan() && count < 50 {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			services = append(services, models.ServiceInfo{
				Name:        name,
				Status:      "running",
				Description: "",
			})
			count++
		}
	}

	return services
}

// Helper functions shared between BSD variants

func getBSDUptime(s SystemPrimitives) int64 {
	cmd := s.ExecCommand("sysctl", "-n", "kern.boottime")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	bootTimeStr := string(output)
	if strings.Contains(bootTimeStr, "sec") {
		parts := strings.Split(bootTimeStr, ",")
		if len(parts) > 0 {
			secPart := strings.TrimSpace(parts[0])
			secPart = strings.TrimPrefix(secPart, "{ sec = ")
			bootTimeSec, err := strconv.ParseInt(secPart, 10, 64)
			if err == nil {
				return bootTimeSec
			}
		}
	}

	return 0
}

func getUnixUsers(s SystemPrimitives) []string {
	var users []string

	file, err := s.OSOpen("/etc/passwd")
	if err != nil {
		if currentUser, err := s.UserCurrent(); err == nil {
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

func getBSDCPUInfo(s SystemPrimitives) models.CPUInfo {
	cpuInfo := models.CPUInfo{
		Cores: 0,
		Model: "Unknown",
	}

	cmd := s.ExecCommand("sysctl", "-n", "hw.model")
	output, err := cmd.Output()
	if err == nil {
		cpuInfo.Model = strings.TrimSpace(string(output))
	}

	cmd = s.ExecCommand("sysctl", "-n", "hw.ncpu")
	output, err = cmd.Output()
	if err == nil {
		cores, _ := strconv.Atoi(strings.TrimSpace(string(output)))
		cpuInfo.Cores = cores
	}

	return cpuInfo
}

func getBSDMemoryInfo(s SystemPrimitives) models.MemoryInfo {
	memInfo := models.MemoryInfo{}

	cmd := s.ExecCommand("sysctl", "-n", "hw.physmem")
	output, err := cmd.Output()
	if err == nil {
		total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		memInfo.Total = total
	}

	// Approximate used memory
	memInfo.Used = memInfo.Total / 2

	return memInfo
}

func getBSDDiskInfo(s SystemPrimitives) []models.DiskInfo {
	var disks []models.DiskInfo
	cmd := s.ExecCommand("df", "-k")
	output, err := cmd.Output()
	if err != nil {
		return disks
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 && strings.HasPrefix(fields[0], "/dev/") {
			total, _ := strconv.ParseUint(fields[1], 10, 64)
			used, _ := strconv.ParseUint(fields[2], 10, 64)
			mountPoint := fields[5]

			disks = append(disks, models.DiskInfo{
				Path:       mountPoint,
				Total:      total * 1024,
				Used:       used * 1024,
				FileSystem: "UFS",
			})
		}
	}

	return disks
}

func getUnixListeningPorts(s SystemPrimitives, seen map[int]bool) []int {
	var ports []int
	cmd := s.ExecCommand("netstat", "-an")
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

func getBSDProcesses(s SystemPrimitives) []models.ProcessInfo {
	var processes []models.ProcessInfo
	cmd := s.ExecCommand("ps", "-axo", "pid,user,comm,%cpu,rss")
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
				Memory: mem * 1024,
			})
			count++
		}
	}

	return processes
}

// Forensics methods implementation for FreeBSD

// CollectBrowserDBFiles collects browser database files
func (f *FreeBSD) CollectBrowserDBFiles(errors *[]string) []models.ForensicFile {
	return collectBrowserDBFilesUnix(f, errors)
}

// CollectRecentFiles collects recently accessed files
func (f *FreeBSD) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	return make([]models.RecentFileEntry, 0) // FreeBSD doesn't have a standard recent files mechanism
}

// CollectCommandHistory collects shell command history
func (f *FreeBSD) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	return collectCommandHistoryUnix(f)
}

// CollectNetworkHistory collects network connection history
func (f *FreeBSD) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	return models.NetworkHistoryData{
		ARPCache: f.CollectARPCacheUnix(),
		DNSCache: make([]models.DNSEntry, 0),
	}
}

// CollectSystemLogs collects system log files
func (f *FreeBSD) CollectSystemLogs(errors *[]string) []models.LogFile {
	return collectSystemLogsUnix(f, errors, []string{
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/security",
	})
}

// CollectScheduledTasks collects scheduled tasks and cron jobs
func (f *FreeBSD) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	return collectScheduledTasksUnix(f)
}

// CollectActiveConnections collects active network connections
func (f *FreeBSD) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	return f.CollectNetstatConnections("freebsd", errors)
}

// CollectHostsFile collects the hosts file
func (f *FreeBSD) CollectHostsFile(errors *[]string) *models.ForensicFile {
	return f.CollectHostsFileCommon("/etc/hosts", errors)
}

// CollectSSHKeys collects SSH key information
func (f *FreeBSD) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return f.CollectSSHKeysCommon()
}

// CollectInstalledSoftware collects installed software information
func (f *FreeBSD) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)

	// pkg info
	if output, err := f.ExecCommand("pkg", "info").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			if fields := strings.Fields(scanner.Text()); len(fields) >= 2 {
				software = append(software, models.SoftwareInfo{
					Name:    fields[0],
					Version: fields[1],
					Source:  "pkg",
				})
			}
		}
	}

	if len(software) > 500 {
		software = software[:500]
	}

	return software
}

// CollectEnvironmentVariables collects environment variables
func (f *FreeBSD) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return f.CollectEnvironmentVariablesCommon()
}

// CollectRecentDownloads collects recently downloaded files
func (f *FreeBSD) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return f.CollectDownloadsCommon(nil)
}

// CollectUSBHistory collects USB device connection history
func (f *FreeBSD) CollectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)

	if output, err := f.ExecCommand("usbconfig", "list").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			devices = append(devices, models.USBDevice{
				Description: line,
				DeviceID:    "usbconfig_entry",
			})
		}
	}

	return devices
}

// CollectPrefetchFiles collects Windows prefetch information (not applicable for FreeBSD)
func (f *FreeBSD) CollectPrefetchFiles(_ *[]string) []models.PrefetchInfo {
	return make([]models.PrefetchInfo, 0)
}

// CollectRecycleBin collects recycle bin contents (not applicable for FreeBSD)
func (f *FreeBSD) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	return make([]models.DeletedFile, 0)
}

// CollectClipboard collects current clipboard content
func (f *FreeBSD) CollectClipboard(errors *[]string) string {
	cmd := f.ExecCommand("xclip", "-selection", "clipboard", "-o")
	if _, err := f.ExecCommand("which", "xclip").Output(); err != nil {
		cmd = f.ExecCommand("xsel", "--clipboard", "--output")
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

// Forensics methods implementation for OpenBSD

// CollectBrowserDBFiles collects browser database files
func (o *OpenBSD) CollectBrowserDBFiles(errors *[]string) []models.ForensicFile {
	return collectBrowserDBFilesUnix(o, errors)
}

// CollectRecentFiles collects recently accessed files
func (o *OpenBSD) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	return make([]models.RecentFileEntry, 0) // OpenBSD doesn't have a standard recent files mechanism
}

// CollectCommandHistory collects shell command history
func (o *OpenBSD) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	return collectCommandHistoryUnix(o)
}

// CollectNetworkHistory collects network connection history
func (o *OpenBSD) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	return models.NetworkHistoryData{
		ARPCache: o.CollectARPCacheUnix(),
		DNSCache: make([]models.DNSEntry, 0),
	}
}

// CollectSystemLogs collects system log files
func (o *OpenBSD) CollectSystemLogs(errors *[]string) []models.LogFile {
	return collectSystemLogsUnix(o, errors, []string{
		"/var/log/messages",
		"/var/log/authlog",
		"/var/log/secure",
	})
}

// CollectScheduledTasks collects scheduled tasks and cron jobs
func (o *OpenBSD) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	return collectScheduledTasksUnix(o)
}

// CollectActiveConnections collects active network connections
func (o *OpenBSD) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	return o.CollectNetstatConnections("openbsd", errors)
}

// CollectHostsFile collects the hosts file
func (o *OpenBSD) CollectHostsFile(errors *[]string) *models.ForensicFile {
	return o.CollectHostsFileCommon("/etc/hosts", errors)
}

// CollectSSHKeys collects SSH key information
func (o *OpenBSD) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return o.CollectSSHKeysCommon()
}

// CollectInstalledSoftware collects installed software information
func (o *OpenBSD) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)

	// pkg_info
	if output, err := o.ExecCommand("pkg_info").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			if fields := strings.Fields(scanner.Text()); len(fields) >= 1 {
				parts := strings.Split(fields[0], "-")
				if len(parts) >= 2 {
					name := strings.Join(parts[:len(parts)-1], "-")
					version := parts[len(parts)-1]
					software = append(software, models.SoftwareInfo{
						Name:    name,
						Version: version,
						Source:  "pkg_info",
					})
				}
			}
		}
	}

	if len(software) > 500 {
		software = software[:500]
	}

	return software
}

// CollectEnvironmentVariables collects environment variables
func (o *OpenBSD) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return o.CollectEnvironmentVariablesCommon()
}

// CollectRecentDownloads collects recently downloaded files
func (o *OpenBSD) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return o.CollectDownloadsCommon(nil)
}

// CollectUSBHistory collects USB device connection history
func (o *OpenBSD) CollectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)

	if output, err := o.ExecCommand("dmesg").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "usb") {
				devices = append(devices, models.USBDevice{
					Description: line,
					DeviceID:    "dmesg_entry",
				})
			}
		}
	}

	return devices
}

// CollectPrefetchFiles collects Windows prefetch information (not applicable for OpenBSD)
func (o *OpenBSD) CollectPrefetchFiles(_ *[]string) []models.PrefetchInfo {
	return make([]models.PrefetchInfo, 0)
}

// CollectRecycleBin collects recycle bin contents (not applicable for OpenBSD)
func (o *OpenBSD) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	return make([]models.DeletedFile, 0)
}

// CollectClipboard collects current clipboard content
func (o *OpenBSD) CollectClipboard(errors *[]string) string {
	cmd := o.ExecCommand("xclip", "-selection", "clipboard", "-o")
	if _, err := o.ExecCommand("which", "xclip").Output(); err != nil {
		cmd = o.ExecCommand("xsel", "--clipboard", "--output")
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

// Helper functions shared by BSD collectors

type bsdCollector interface {
	SystemPrimitives
	CopyFileArtifact(src, name, category string) (*models.ForensicFile, error)
	ReadFileWithLimit(path string, maxSize int64) (string, bool, error)
}

//nolint:dupl // Similar implementation for BSD, slight differences in paths
func collectBrowserDBFilesUnix(collector bsdCollector, errors *[]string) []models.ForensicFile {
	files := make([]models.ForensicFile, 0)
	homeDir, _ := collector.OSUserHomeDir()

	// Chrome
	chromeBase := filepath.Join(homeDir, ".config", "chromium", "Default")
	for _, name := range []string{"History", "Cookies"} {
		src := filepath.Join(chromeBase, name)
		if artifact, err := collector.CopyFileArtifact(src, "chrome_"+strings.ToLower(name), "chrome"); err == nil {
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
				if artifact, err := collector.CopyFileArtifact(src, "firefox_"+strings.TrimSuffix(name, ".sqlite"), "firefox"); err == nil {
					files = append(files, *artifact)
				} else if errors != nil {
					*errors = append(*errors, err.Error())
				}
			}
		}
	}

	return files
}

func collectCommandHistoryUnix(collector SystemPrimitives) []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)
	homeDir, err := collector.OSUserHomeDir()
	if err != nil {
		return commands
	}

	historyFiles := []struct {
		path  string
		shell string
	}{
		{filepath.Join(homeDir, ".bash_history"), "bash"},
		{filepath.Join(homeDir, ".zsh_history"), "zsh"},
		{filepath.Join(homeDir, ".sh_history"), "sh"},
	}

	for _, hf := range historyFiles {
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := collector.OSReadFile(hf.path); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					commands = append(commands, models.CommandEntry{
						Shell:   hf.shell,
						Command: line,
						LineNum: i + 1,
					})
				}
			}
		}
	}

	return commands
}

func collectSystemLogsUnix(collector bsdCollector, errors *[]string, logPaths []string) []models.LogFile {
	logs := make([]models.LogFile, 0)
	maxLogSize := int64(1024 * 1024)

	for _, logPath := range logPaths {
		info, err := collector.OSStat(logPath)
		if err != nil {
			continue
		}

		content, truncated, err := collector.ReadFileWithLimit(logPath, maxLogSize)
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

func collectScheduledTasksUnix(collector SystemPrimitives) []models.ScheduledTask {
	tasks := make([]models.ScheduledTask, 0)

	// User crontab
	if output, err := collector.ExecCommand("crontab", "-l").Output(); err == nil {
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

	// System cron directories
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"} {
		if entries, err := collector.OSReadDir(dir); err == nil {
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

	return tasks
}
