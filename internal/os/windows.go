// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/ilexum-group/tracium/pkg/models"
)

// Windows implements Collector for Windows systems
type Windows struct {
	*Default
}

// NewWindows creates a new Windows instance
func NewWindows() Collector {
	return NewWindowsWithDefault(NewDefault())
}

// NewWindowsWithDefault creates a new Windows instance with a provided Default.
func NewWindowsWithDefault(def *Default) Collector {
	return &Windows{
		Default: def,
	}
}

// GetCurrentUser returns the current user name
func (w *Windows) GetCurrentUser() (string, error) {
	if !w.IsLive() {
		return "unknown", nil
	}
	currentUser, err := w.UserCurrent()
	// On Windows, username may include domain (DOMAIN\username)
	// Extract just the username part
	username := currentUser.Username
	if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		username = parts[len(parts)-1]
	}

	return username, err
}

// GetUptime returns the system uptime in seconds
func (w *Windows) GetUptime() int64 {
	if !w.IsLive() {
		return 0
	}
	cmd := w.ExecCommand("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	bootTimeStr := strings.TrimSpace(string(output))
	bootTime, err := time.Parse("20060102150405.000000-700", bootTimeStr)
	if err == nil {
		return int64(time.Since(bootTime).Seconds())
	}

	return 0
}

// GetUsers returns the list of system users
func (w *Windows) GetUsers() []string {
	var users []string
	fmt.Printf("[windows] GetUsers: live=%v\n", w.IsLive())

	base := w.OSGetenv("SystemDrive")
	if base == "" {
		base = "C:"
	}
	usersDir := filepath.Join(base, "Users")
	fmt.Printf("[windows] GetUsers: scanning usersDir=%s\n", usersDir)
	if entries, err := w.OSReadDir(usersDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if name == "Default" || name == "Default User" || name == "All Users" || name == "Public" {
				continue
			}
			users = append(users, name)
		}
		fmt.Printf("[windows] GetUsers: dir scan found %d users\n", len(users))
	} else {
		fmt.Printf("[windows] GetUsers: read dir failed: %s err=%v\n", usersDir, err)
	}

	if len(users) == 0 {
		if w.IsLive() {
			if currentUser, err := w.UserCurrent(); err == nil {
				users = append(users, currentUser.Username)
				fmt.Printf("[windows] GetUsers: live fallback user=%s\n", currentUser.Username)
			} else {
				fmt.Printf("[windows] GetUsers: live fallback failed err=%v\n", err)
			}
		}
		if !w.IsLive() {
			fmt.Printf("[windows] GetUsers: fallback to registry\n")
			registryUsers := w.collectUsersFromRegistry()
			fmt.Printf("[windows] GetUsers: registry users=%d\n", len(registryUsers))
			users = append(users, registryUsers...)
		}
	}

	return users
}

// GetCPUInfo returns CPU information
func (w *Windows) GetCPUInfo() models.CPUInfo {
	cpuInfo := models.CPUInfo{
		Cores: 0,
		Model: "Unknown",
	}
	if !w.IsLive() {
		return cpuInfo
	}

	cmd := w.ExecCommand("powershell", "-Command", "(Get-CimInstance Win32_Processor).Name")
	output, err := cmd.Output()
	if err == nil {
		cpuInfo.Model = strings.TrimSpace(string(output))
	}

	cmd = w.ExecCommand("powershell", "-Command", "(Get-CimInstance Win32_Processor).NumberOfCores")
	output, err = cmd.Output()
	if err == nil {
		cores, _ := strconv.Atoi(strings.TrimSpace(string(output)))
		cpuInfo.Cores = cores
	}

	return cpuInfo
}

// GetMemoryInfo returns memory information
func (w *Windows) GetMemoryInfo() models.MemoryInfo {
	memInfo := models.MemoryInfo{}
	if !w.IsLive() {
		return memInfo
	}

	// Get total memory
	cmd := w.ExecCommand("powershell", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
	output, err := cmd.Output()
	if err == nil {
		total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		memInfo.Total = total
	}

	// Get free memory
	cmd = w.ExecCommand("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory")
	output, err = cmd.Output()
	if err == nil {
		free, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		memInfo.Used = memInfo.Total - (free * 1024) // Convert KB to bytes
	}

	return memInfo
}

// GetDiskInfo returns disk information
func (w *Windows) GetDiskInfo() []models.DiskInfo {
	var disks []models.DiskInfo
	if !w.IsLive() {
		return disks
	}

	cmd := w.ExecCommand("powershell", "-Command", "Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null} | Select-Object Name,@{Name='Total';Expression={$_.Used+$_.Free}},Used | ConvertTo-Json")
	output, err := cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		if len(outputStr) > 0 {
			lines := strings.Split(outputStr, "\n")
			var currentDrive models.DiskInfo

			for _, line := range lines {
				line = strings.TrimSpace(line)
				switch {
				case strings.Contains(line, `"Name"`):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						name := strings.Trim(strings.TrimSuffix(parts[1], ","), ` "`)
						currentDrive.Path = name + ":\\"
					}
				case strings.Contains(line, `"Total"`):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						val := strings.TrimSuffix(strings.TrimSpace(parts[1]), ",")
						total, _ := strconv.ParseUint(val, 10, 64)
						currentDrive.Total = total
					}
				case strings.Contains(line, `"Used"`):
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						val := strings.TrimSpace(parts[1])
						used, _ := strconv.ParseUint(val, 10, 64)
						currentDrive.Used = used
						currentDrive.FileSystem = "NTFS"

						if currentDrive.Path != "" && currentDrive.Total > 0 {
							disks = append(disks, currentDrive)
							currentDrive = models.DiskInfo{}
						}
					}
				}
			}
		}
	}

	// Fallback: try wmic
	if len(disks) == 0 {
		cmd = w.ExecCommand("wmic", "logicaldisk", "get", "caption,size,freespace")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			scanner.Scan() // Skip header

			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 3 {
					path := fields[0]
					freeStr := fields[1]
					totalStr := fields[2]

					total, _ := strconv.ParseUint(totalStr, 10, 64)
					free, _ := strconv.ParseUint(freeStr, 10, 64)

					if total > 0 {
						disks = append(disks, models.DiskInfo{
							Path:       path,
							Total:      total,
							Used:       total - free,
							FileSystem: "NTFS",
						})
					}
				}
			}
		}
	}

	return disks
}

// GetListeningPorts returns listening ports
//
//nolint:dupl // Similar netstat parsing, Windows-specific output format differs
func (w *Windows) GetListeningPorts(seen map[int]bool) []int {
	var ports []int
	if !w.IsLive() {
		return ports
	}
	cmd := w.ExecCommand("netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return ports
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "LISTENING") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) > 1 {
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
func (w *Windows) GetProcesses() []models.ProcessInfo {
	var processes []models.ProcessInfo
	if !w.IsLive() {
		return processes
	}

	cmd := w.ExecCommand("powershell", "-Command",
		"Get-Process | Select-Object -First 100 Id,Name,@{Name='User';Expression={(Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\").GetOwner().User}},CPU,@{Name='Memory';Expression={$_.WorkingSet64}} | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			line := scanner.Text()
			line = strings.Trim(line, "\"")
			parts := strings.Split(line, "\",\"")

			if len(parts) >= 5 {
				pid, _ := strconv.Atoi(strings.Trim(parts[0], "\""))
				name := strings.Trim(parts[1], "\"")
				userName := strings.Trim(parts[2], "\"")
				cpu, _ := strconv.ParseFloat(strings.Trim(parts[3], "\""), 64)
				mem, _ := strconv.ParseUint(strings.Trim(parts[4], "\""), 10, 64)

				processes = append(processes, models.ProcessInfo{
					PID:    pid,
					Name:   name,
					User:   userName,
					CPU:    cpu,
					Memory: mem,
				})
			}
		}
	}

	// Fallback to simple tasklist
	if len(processes) == 0 {
		cmd = w.ExecCommand("tasklist", "/FO", "CSV", "/NH")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			count := 0

			for scanner.Scan() && count < 100 {
				line := scanner.Text()
				parts := strings.Split(line, "\",\"")
				if len(parts) >= 2 {
					name := strings.Trim(parts[0], "\"")
					pidStr := strings.Trim(parts[1], "\"")
					pid, _ := strconv.Atoi(pidStr)

					processes = append(processes, models.ProcessInfo{
						PID:    pid,
						Name:   name,
						User:   "Unknown",
						CPU:    0.0,
						Memory: 0,
					})
					count++
				}
			}
		}
	}

	return processes
}

// GetServices returns system services
func (w *Windows) GetServices() []models.ServiceInfo {
	var services []models.ServiceInfo
	if !w.IsLive() {
		fmt.Printf("[windows] GetServices: using registry (post-mortem)\n")
		registryServices := w.collectServicesFromRegistry()
		fmt.Printf("[windows] GetServices: registry services=%d\n", len(registryServices))
		return registryServices
	}

	cmd := w.ExecCommand("powershell", "-Command",
		"Get-Service | Select-Object -First 50 Name,Status,DisplayName | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, "\",\"")
			if len(parts) >= 3 {
				name := strings.Trim(parts[0], "\"")
				statusStr := strings.Trim(parts[1], "\"")
				description := strings.Trim(parts[2], "\"")

				status := "unknown"
				if strings.EqualFold(statusStr, "Running") {
					status = "running"
				} else if strings.EqualFold(statusStr, "Stopped") {
					status = "stopped"
				}

				services = append(services, models.ServiceInfo{
					Name:        name,
					Status:      status,
					Description: description,
				})
			}
		}
		fmt.Printf("[windows] GetServices: powershell services=%d\n", len(services))
		return services
	}
	fmt.Printf("[windows] GetServices: powershell failed err=%v\n", err)

	// Fallback to sc query
	cmd = w.ExecCommand("sc", "query")
	output, err = cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	var currentService models.ServiceInfo
	count := 0

	for scanner.Scan() && count < 50 {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "SERVICE_NAME:"):
			if currentService.Name != "" {
				services = append(services, currentService)
				count++
			}
			currentService = models.ServiceInfo{
				Name: strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:")),
			}
		case strings.HasPrefix(line, "DISPLAY_NAME:"):
			currentService.Description = strings.TrimSpace(strings.TrimPrefix(line, "DISPLAY_NAME:"))
		case strings.Contains(line, "STATE"):
			switch {
			case strings.Contains(line, "RUNNING"):
				currentService.Status = "running"
			case strings.Contains(line, "STOPPED"):
				currentService.Status = "stopped"
			default:
				currentService.Status = "unknown"
			}
		}
	}

	if currentService.Name != "" && count < 50 {
		services = append(services, currentService)
	}

	fmt.Printf("[windows] GetServices: sc query services=%d\n", len(services))
	return services
}

// Forensics methods implementation for Windows

// CollectBrowserArtifacts collects structured browser artifacts on Windows (delegates to Default)
func (w *Windows) CollectBrowserArtifacts(errors *[]string) models.BrowserArtifacts {
	def := Default{fileAccessor: w.fileAccessor, logFunc: w.logFunc}
	return def.CollectBrowserArtifacts(errors)
}

// CollectCommunicationArtifacts collects communication artifacts on Windows (delegates to Default)
func (w *Windows) CollectCommunicationArtifacts(errors *[]string) models.CommunicationArtifacts {
	def := Default{fileAccessor: w.fileAccessor, logFunc: w.logFunc}
	return def.CollectCommunicationArtifacts(errors)
}

// CollectRecentFiles collects recently accessed files
func (w *Windows) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)
	homeDirs, err := w.OSUserHomeDirs()
	if err != nil {
		return files
	}

	for _, homeDir := range homeDirs {
		recentPath := filepath.Join(homeDir, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
		if entries, err := w.OSReadDir(recentPath); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".lnk" {
					if info, err := entry.Info(); err == nil {
						files = append(files, models.RecentFileEntry{
							FilePath:     filepath.Join(recentPath, entry.Name()),
							FileName:     entry.Name(),
							AccessedTime: info.ModTime().Unix(),
							Source:       "recent_folder",
						})
					}
				}
			}
		}
	}

	return files
}

// CollectCommandHistory collects PowerShell command history
func (w *Windows) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)
	homeDirs, err := w.OSUserHomeDirs()
	if err != nil {
		return commands
	}

	for _, homeDir := range homeDirs {
		// PowerShell history
		historyPaths := []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
			filepath.Join(homeDir, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "Visual Studio Code Host_history.txt"),
		}

		for _, historyPath := range historyPaths {
			//nolint:gosec // G304: path constructed from trusted UserHomeDir
			if content, err := w.OSReadFile(historyPath); err == nil {
				for i, line := range strings.Split(string(content), "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						commands = append(commands, models.CommandEntry{
							Shell:   "powershell",
							Command: line,
							LineNum: i + 1,
						})
					}
				}
			}
		}
	}

	// CMD history (from registry) - live only
	if w.IsLive() {
		cmd := w.ExecCommand("powershell", "-Command", "Get-Content -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU' -ErrorAction SilentlyContinue")
		if output, err := cmd.Output(); err == nil {
			for i, line := range strings.Split(string(output), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					commands = append(commands, models.CommandEntry{
						Shell:   "cmd",
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
func (w *Windows) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	networkHistory := models.NetworkHistoryData{
		ARPCache: make([]models.ARPEntry, 0),
		DNSCache: make([]models.DNSEntry, 0),
	}
	if !w.IsLive() {
		return networkHistory
	}

	// ARP cache
	if output, err := w.ExecCommand("arp", "-a").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				networkHistory.ARPCache = append(networkHistory.ARPCache, models.ARPEntry{
					IPAddress:  fields[0],
					MACAddress: fields[1],
				})
			}
		}
	}

	// DNS cache
	if output, err := w.ExecCommand("powershell", "-Command", "Get-DnsClientCache | Select-Object Entry,Data").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "Entry") && !strings.HasPrefix(line, "---") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					networkHistory.DNSCache = append(networkHistory.DNSCache, models.DNSEntry{
						Hostname:  fields[0],
						IPAddress: []string{fields[1]},
					})
				}
			}
		}
	}

	return networkHistory
}

// CollectSystemLogs collects Windows Event Logs
func (w *Windows) CollectSystemLogs(errors *[]string) []models.LogFile {
	logs := make([]models.LogFile, 0)
	if !w.IsLive() {
		return logs
	}

	logNames := []string{"System", "Application", "Security"}
	for _, logName := range logNames {
		cmd := w.ExecCommand("powershell", "-Command",
			fmt.Sprintf("Get-EventLog -LogName %s -Newest 100 | Format-List", logName))

		output, err := cmd.Output()
		if err != nil {
			if errors != nil {
				*errors = append(*errors, fmt.Sprintf("failed to read %s log: %v", logName, err))
			}
			continue
		}

		content := string(output)
		truncated := false
		if len(content) > 1024*1024 {
			content = content[:1024*1024]
			truncated = true
		}

		logs = append(logs, models.LogFile{
			Name:      logName,
			Path:      fmt.Sprintf("EventLog:%s", logName),
			Size:      int64(len(content)),
			Content:   content,
			Truncated: truncated,
		})
	}

	return logs
}

// CollectScheduledTasks collects scheduled tasks
func (w *Windows) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	tasks := make([]models.ScheduledTask, 0)
	fmt.Printf("[windows] CollectScheduledTasks: live=%v\n", w.IsLive())
	fileTasks := w.collectScheduledTasksFromFiles()
	if len(fileTasks) > 0 {
		fmt.Printf("[windows] CollectScheduledTasks: parsed %d task XML files\n", len(fileTasks))
		return fileTasks
	}
	if !w.IsLive() {
		return tasks
	}

	cmd := w.ExecCommand("schtasks", "/query", "/fo", "LIST", "/v")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[windows] CollectScheduledTasks: schtasks failed err=%v\n", err)
		return tasks
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	var currentTask models.ScheduledTask

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if currentTask.Name != "" {
				tasks = append(tasks, currentTask)
				currentTask = models.ScheduledTask{}
			}
			continue
		}

		if strings.HasPrefix(line, "TaskName:") {
			currentTask.Name = strings.TrimSpace(strings.TrimPrefix(line, "TaskName:"))
			continue
		}
		if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			currentTask.Enabled = status == "Ready" || status == "Running"
			continue
		}
		if strings.HasPrefix(line, "Task To Run:") {
			currentTask.Command = strings.TrimSpace(strings.TrimPrefix(line, "Task To Run:"))
		}
	}

	if currentTask.Name != "" {
		tasks = append(tasks, currentTask)
	}

	currentTask.Source = "scheduled_tasks"
	fmt.Printf("[windows] CollectScheduledTasks: schtasks parsed %d tasks\n", len(tasks))
	return tasks
}

type windowsTaskXML struct {
	RegistrationInfo struct {
		URI string `xml:"URI"`
	} `xml:"RegistrationInfo"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func (w *Windows) collectScheduledTasksFromFiles() []models.ScheduledTask {
	basePath := "C:\\Windows\\System32\\Tasks"
	maxTasks := 200
	collected := make([]models.ScheduledTask, 0)
	fmt.Printf("[windows] collectScheduledTasksFromFiles: base=%s\n", basePath)

	var walk func(path string)
	walk = func(path string) {
		if len(collected) >= maxTasks {
			return
		}
		entries, err := w.OSReadDir(path)
		if err != nil {
			fmt.Printf("[windows] collectScheduledTasksFromFiles: read dir failed: %s err=%v\n", path, err)
			return
		}
		for _, entry := range entries {
			if len(collected) >= maxTasks {
				return
			}
			childPath := filepath.Join(path, entry.Name())
			if entry.IsDir() {
				walk(childPath)
				continue
			}
			data, err := w.OSReadFile(childPath)
			if err != nil || len(data) == 0 {
				if err != nil {
					fmt.Printf("[windows] collectScheduledTasksFromFiles: read failed: %s err=%v\n", childPath, err)
				}
				continue
			}
			data = normalizeTaskXML(data)
			var task windowsTaskXML
			if err := xml.Unmarshal(data, &task); err != nil {
				fmt.Printf("[windows] collectScheduledTasksFromFiles: xml parse failed: %s err=%v\n", childPath, err)
				continue
			}
			name := task.RegistrationInfo.URI
			if name == "" {
				name = childPath
			}
			command := strings.TrimSpace(task.Actions.Exec.Command)
			if command == "" {
				continue
			}
			args := strings.TrimSpace(task.Actions.Exec.Arguments)
			if args != "" {
				command = fmt.Sprintf("%s %s", command, args)
			}
			collected = append(collected, models.ScheduledTask{
				Name:    name,
				Command: command,
				Source:  "task_xml",
				Enabled: true,
			})
		}
	}

	walk(basePath)
	fmt.Printf("[windows] collectScheduledTasksFromFiles: collected=%d\n", len(collected))
	return collected
}

func normalizeTaskXML(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	// UTF-16 BOM detection
	if data[0] == 0xFF && data[1] == 0xFE {
		return utf16ToUTF8(data[2:], true)
	}
	if data[0] == 0xFE && data[1] == 0xFF {
		return utf16ToUTF8(data[2:], false)
	}
	// Heuristic: contains null bytes => likely UTF-16
	if bytes.IndexByte(data[:minInt(len(data), 512)], 0x00) != -1 {
		return utf16ToUTF8(data, likelyUTF16LE(data))
	}
	return data
}

func utf16ToUTF8(data []byte, littleEndian bool) []byte {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		if littleEndian {
			u16 = append(u16, uint16(data[i])|uint16(data[i+1])<<8)
		} else {
			u16 = append(u16, uint16(data[i])<<8|uint16(data[i+1]))
		}
	}
	return []byte(string(utf16.Decode(u16)))
}

func likelyUTF16LE(data []byte) bool {
	// If even bytes are ASCII and odd bytes are 0x00, assume LE.
	limit := minInt(len(data), 256)
	zeroOdd := 0
	zeroEven := 0
	for i := 0; i+1 < limit; i += 2 {
		if data[i] == 0x00 {
			zeroEven++
		}
		if data[i+1] == 0x00 {
			zeroOdd++
		}
	}
	return zeroOdd >= zeroEven
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CollectActiveConnections collects active network connections
func (w *Windows) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	return w.CollectNetstatConnections("windows", errors)
}

// CollectHostsFile collects the hosts file
func (w *Windows) CollectHostsFile(errors *[]string) *models.ForensicFile {
	return w.CollectHostsFileCommon("C:\\Windows\\System32\\drivers\\etc\\hosts", errors)
}

// CollectSSHKeys collects SSH key information
func (w *Windows) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return w.CollectSSHKeysCommon()
}

// CollectInstalledSoftware collects installed software information
func (w *Windows) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)
	if !w.IsLive() {
		fmt.Printf("[windows] CollectInstalledSoftware: using registry (post-mortem)\n")
		registrySoftware := w.collectInstalledSoftwareFromRegistry()
		fmt.Printf("[windows] CollectInstalledSoftware: registry count=%d\n", len(registrySoftware))
		return registrySoftware
	}
	if registrySoftware := w.collectInstalledSoftwareFromRegistry(); len(registrySoftware) > 0 {
		fmt.Printf("[windows] CollectInstalledSoftware: using registry (live) count=%d\n", len(registrySoftware))
		return registrySoftware
	}

	cmd := w.ExecCommand("powershell", "-Command",
		"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher")

	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "---") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 2 {
				software = append(software, models.SoftwareInfo{
					Name:      fields[0],
					Version:   fields[1],
					Publisher: strings.Join(fields[2:], " "),
					Source:    "registry",
				})
			}
		}
	}
	if err != nil {
		fmt.Printf("[windows] CollectInstalledSoftware: powershell failed err=%v\n", err)
	}
	fmt.Printf("[windows] CollectInstalledSoftware: powershell parsed %d entries\n", len(software))

	return software
}

// CollectEnvironmentVariables collects environment variables
func (w *Windows) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return w.CollectEnvironmentVariablesCommon()
}

// CollectRecentDownloads collects recently downloaded files
func (w *Windows) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return w.CollectDownloadsCommon(nil)
}

// CollectUSBHistory collects USB device connection history
func (w *Windows) CollectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)
	if !w.IsLive() {
		fmt.Printf("[windows] CollectUSBHistory: using registry (post-mortem)\n")
		registryDevices := w.collectUSBHistoryFromRegistry()
		fmt.Printf("[windows] CollectUSBHistory: registry count=%d\n", len(registryDevices))
		return registryDevices
	}

	cmd := w.ExecCommand("powershell", "-Command",
		"Get-PnpDevice -Class USB | Select-Object FriendlyName,InstanceId,Status")

	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "---") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 2 {
				devices = append(devices, models.USBDevice{
					ProductID:   fields[0],
					DeviceID:    fields[1],
					Description: line,
				})
			}
		}
	}
	if err != nil {
		fmt.Printf("[windows] CollectUSBHistory: powershell failed err=%v\n", err)
	}
	fmt.Printf("[windows] CollectUSBHistory: powershell parsed %d entries\n", len(devices))

	return devices
}

// CollectPrefetchFiles collects Windows prefetch files
func (w *Windows) CollectPrefetchFiles(errors *[]string) []models.PrefetchInfo {
	prefetchFiles := make([]models.PrefetchInfo, 0)
	prefetchPath := "C:\\Windows\\Prefetch"

	entries, err := w.OSReadDir(prefetchPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to read prefetch directory: %v", err))
		}
		return prefetchFiles
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".pf" {
			if _, err := entry.Info(); err == nil {
				prefetchFiles = append(prefetchFiles, models.PrefetchInfo{
					FileName: entry.Name(),
				})
			}
		}
	}

	return prefetchFiles
}

// CollectRecycleBin collects recycle bin contents
func (w *Windows) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	deletedFiles := make([]models.DeletedFile, 0)
	if !w.IsLive() {
		return deletedFiles
	}

	cmd := w.ExecCommand("powershell", "-Command",
		"(New-Object -ComObject Shell.Application).NameSpace(0xa).Items() | Select-Object Name,Size,Path")

	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "---") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 3 {
				size, _ := strconv.ParseInt(fields[1], 10, 64)
				deletedFiles = append(deletedFiles, models.DeletedFile{
					FileName:     fields[0],
					Size:         size,
					DeletedPath:  fields[2],
					OriginalPath: "unknown",
					DeletedTime:  time.Now().Unix(),
				})
			}
		}
	}

	return deletedFiles
}

// CollectClipboard collects current clipboard content
func (w *Windows) CollectClipboard(errors *[]string) string {
	if !w.IsLive() {
		return ""
	}
	cmd := w.ExecCommand("powershell", "-Command", "Get-Clipboard")
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

// CollectFilesystemTree collects filesystem tree for Windows
func (w *Windows) CollectFilesystemTree() models.FilesystemTree {
	if w.IsLive() {
		return w.collectFilesystemTreeLive()
	}
	return w.collectFilesystemTreeImage()
}

func (w *Windows) collectFilesystemTreeLive() models.FilesystemTree {
	root := w.treeRoots()
	rootPath := "C:\\"
	if len(root) > 0 {
		rootPath = root[0]
	}
	ps := fmt.Sprintf("Get-ChildItem '%s' -Recurse -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, Mode, CreationTimeUtc, LastWriteTimeUtc | ConvertTo-Csv -NoTypeInformation", rootPath)
	cmd := w.ExecCommand("powershell", "-Command", ps)
	output, err := cmd.Output()
	if err != nil {
		return models.FilesystemTree{Nodes: w.collectTreeWithTreeCommand()}
	}
	return models.FilesystemTree{Nodes: parseWindowsPSOutput(output)}
}

func parseWindowsPSOutput(output []byte) []models.TreeNode {
	reader := csv.NewReader(bytes.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return []models.TreeNode{}
	}

	idx := make(map[string]int)
	for i, name := range records[0] {
		idx[strings.TrimSpace(name)] = i
	}

	get := func(row []string, key string) string {
		pos, ok := idx[key]
		if !ok || pos >= len(row) {
			return ""
		}
		return row[pos]
	}

	nodes := make([]models.TreeNode, 0, len(records)-1)
	for _, row := range records[1:] {
		pathStr := strings.TrimSpace(get(row, "FullName"))
		if pathStr == "" {
			continue
		}
		mode := strings.TrimSpace(get(row, "Mode"))
		fileType := "file"
		if strings.HasPrefix(mode, "d") {
			fileType = "directory"
		}
		size := parseInt64(get(row, "Length"))
		ctime := parseTimeToUnix(get(row, "CreationTimeUtc"))
		mtime := parseTimeToUnix(get(row, "LastWriteTimeUtc"))
		nodes = append(nodes, models.TreeNode{
			Path:         pathStr,
			Name:         filepath.Base(pathStr),
			Parent:       parentPath(pathStr),
			Type:         fileType,
			Size:         size,
			Permissions:  mode,
			CreatedTime:  ctime,
			ModifiedTime: mtime,
		})
	}
	return nodes
}
