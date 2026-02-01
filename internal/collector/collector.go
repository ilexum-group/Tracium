// Package collector provides functions to collect system, hardware, network, and security information.
package collector

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ilexum/tracium/internal/models"
)

// CollectSystemInfo collects basic system information
func CollectSystemInfo() models.SystemInfo {
	hostname, _ := os.Hostname()
	users := getUsers()

	return models.SystemInfo{
		OS:           runtime.GOOS,
		Hostname:     hostname,
		Architecture: runtime.GOARCH,
		Uptime:       getUptime(),
		Users:        users,
	}
}

// CollectHardwareInfo collects hardware information
func CollectHardwareInfo() models.HardwareInfo {
	return models.HardwareInfo{
		CPU:    getCPUInfo(),
		Memory: getMemoryInfo(),
		Disk:   getDiskInfo(),
	}
}

// CollectNetworkInfo collects network information
func CollectNetworkInfo() models.NetworkInfo {
	interfaces := getInterfaces()
	ports := getListeningPorts()

	return models.NetworkInfo{
		Interfaces:     interfaces,
		ListeningPorts: ports,
	}
}

// CollectSecurityInfo collects security-related information
func CollectSecurityInfo() models.SecurityInfo {
	processes := getProcesses()
	services := getServices()

	return models.SecurityInfo{
		Processes: processes,
		Services:  services,
	}
}

// Helper functions for system information collection

func getUsers() []string {
	var users []string

	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd":
		// Try to read /etc/passwd
		file, err := os.Open("/etc/passwd")
		if err == nil {
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
		}
	case "windows":
		// Use PowerShell to get user list
		cmd := exec.Command("powershell", "-Command", "Get-LocalUser | Select-Object -ExpandProperty Name")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				username := strings.TrimSpace(scanner.Text())
				if username != "" {
					users = append(users, username)
				}
			}
		}
	}

	// Fallback to current user if nothing found
	if len(users) == 0 {
		currentUser, err := user.Current()
		if err == nil {
			users = append(users, currentUser.Username)
		}
	}

	return users
}

func getUptime() int64 {
	var uptime int64

	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			parts := strings.Fields(string(data))
			if len(parts) > 0 {
				uptimeFloat, err := strconv.ParseFloat(parts[0], 64)
				if err == nil {
					uptime = int64(uptimeFloat)
				}
			}
		}
	case "darwin", "freebsd", "openbsd":
		cmd := exec.Command("sysctl", "-n", "kern.boottime")
		output, err := cmd.Output()
		if err == nil {
			// Parse output like: { sec = 1234567890, usec = 0 }
			bootTimeStr := string(output)
			if strings.Contains(bootTimeStr, "sec") {
				parts := strings.Split(bootTimeStr, ",")
				if len(parts) > 0 {
					secPart := strings.TrimSpace(parts[0])
					secPart = strings.TrimPrefix(secPart, "{ sec = ")
					bootTimeSec, err := strconv.ParseInt(secPart, 10, 64)
					if err == nil {
						uptime = time.Now().Unix() - bootTimeSec
					}
				}
			}
		}
	case "windows":
		cmd := exec.Command("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
		output, err := cmd.Output()
		if err == nil {
			// Parse the output and calculate uptime
			bootTimeStr := strings.TrimSpace(string(output))
			bootTime, err := time.Parse("20060102150405.000000-700", bootTimeStr)
			if err == nil {
				uptime = int64(time.Since(bootTime).Seconds())
			}
		}
	}

	// If we couldn't get real uptime, return 0
	return uptime
}

func getCPUInfo() models.CPUInfo {
	cpuInfo := models.CPUInfo{
		Cores: runtime.NumCPU(),
		Model: "Unknown",
	}

	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/cpuinfo")
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "model name") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						cpuInfo.Model = strings.TrimSpace(parts[1])
						break
					}
				}
			}
		}
	case "darwin":
		cmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
		output, err := cmd.Output()
		if err == nil {
			cpuInfo.Model = strings.TrimSpace(string(output))
		}
	case "windows":
		cmd := exec.Command("powershell", "-Command", "(Get-CimInstance Win32_Processor).Name")
		output, err := cmd.Output()
		if err == nil {
			cpuInfo.Model = strings.TrimSpace(string(output))
		}
	case "freebsd", "openbsd":
		cmd := exec.Command("sysctl", "-n", "hw.model")
		output, err := cmd.Output()
		if err == nil {
			cpuInfo.Model = strings.TrimSpace(string(output))
		}
	}

	return cpuInfo
}

func getMemoryInfo() models.MemoryInfo {
	memInfo := models.MemoryInfo{}

	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/meminfo")
		if err == nil {
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
		}
	case "darwin":
		// Get total memory
		cmd := exec.Command("sysctl", "-n", "hw.memsize")
		output, err := cmd.Output()
		if err == nil {
			total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
			memInfo.Total = total
		}

		// Get used memory via vm_stat
		cmd = exec.Command("vm_stat")
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
	case "windows":
		// Get total memory
		cmd := exec.Command("powershell", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
		output, err := cmd.Output()
		if err == nil {
			total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
			memInfo.Total = total
		}

		// Get free memory
		cmd = exec.Command("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory")
		output, err = cmd.Output()
		if err == nil {
			free, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
			memInfo.Used = memInfo.Total - (free * 1024) // Convert KB to bytes
		}
	case "freebsd", "openbsd":
		cmd := exec.Command("sysctl", "-n", "hw.physmem")
		output, err := cmd.Output()
		if err == nil {
			total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
			memInfo.Total = total
		}

		// Approximate used memory
		memInfo.Used = memInfo.Total / 2
	}

	return memInfo
}

func getDiskInfo() []models.DiskInfo {
	var disks []models.DiskInfo

	switch runtime.GOOS {
	case "linux":
		disks = getDiskInfoLinux()
	case "darwin":
		disks = getDiskInfoDarwin()
	case "windows":
		disks = getDiskInfoWindows()
	case "freebsd", "openbsd":
		disks = getDiskInfoBSD()
	}

	// If no disks found, return at least root/C:
	if len(disks) == 0 {
		rootPath := "/"
		if runtime.GOOS == "windows" {
			rootPath = "C:\\"
		}
		disks = append(disks, models.DiskInfo{
			Path:       rootPath,
			Total:      0,
			Used:       0,
			FileSystem: "unknown",
		})
	}

	return disks
}

func getDiskInfoLinux() []models.DiskInfo {
	var disks []models.DiskInfo
	data, err := os.ReadFile("/proc/mounts")
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

			// Use df to get disk usage
			//nolint:gosec // G204: mountPoint is validated from /etc/fstab
			cmd := exec.Command("df", "-B1", mountPoint)
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

func getDiskInfoDarwin() []models.DiskInfo {
	var disks []models.DiskInfo
	cmd := exec.Command("df", "-k")
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

func getDiskInfoWindows() []models.DiskInfo {
	var disks []models.DiskInfo
	cmd := exec.Command("powershell", "-Command", "Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null} | Select-Object Name,@{Name='Total';Expression={$_.Used+$_.Free}},Used | ConvertTo-Json")
	output, err := cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		if len(outputStr) > 0 {
			// Simple JSON-like parsing for drive info
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
		cmd = exec.Command("wmic", "logicaldisk", "get", "caption,size,freespace")
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

func getDiskInfoBSD() []models.DiskInfo {
	var disks []models.DiskInfo
	cmd := exec.Command("df", "-k")
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

func getInterfaces() []models.InterfaceInfo {
	var interfaces []models.InterfaceInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaces
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		var ips []string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}

		interfaces = append(interfaces, models.InterfaceInfo{
			Name: iface.Name,
			IPs:  ips,
			MAC:  iface.HardwareAddr.String(),
		})
	}

	return interfaces
}

func getListeningPorts() []int {
	var ports []int
	seen := make(map[int]bool)

	switch runtime.GOOS {
	case "linux":
		ports = getListeningPortsLinux(seen)
	case "darwin", "freebsd", "openbsd":
		ports = getListeningPortsUnix(seen)
	case "windows":
		ports = getListeningPortsWindows(seen)
	}

	return ports
}

func getListeningPortsLinux(seen map[int]bool) []int {
	var ports []int

	// Parse /proc/net/tcp and /proc/net/tcp6
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		//nolint:gosec // G304: /proc files are trusted system paths
		data, err := os.ReadFile(file)
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
					// Port is in hex
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
		data, err := os.ReadFile(file)
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

			// State 07 = LISTEN for UDP
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

func getListeningPortsUnix(seen map[int]bool) []int {
	var ports []int
	cmd := exec.Command("netstat", "-an")
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

func getListeningPortsWindows(seen map[int]bool) []int {
	var ports []int
	cmd := exec.Command("netstat", "-an")
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

func getProcesses() []models.ProcessInfo {
	var processes []models.ProcessInfo

	switch runtime.GOOS {
	case "linux":
		processes = getProcessesLinux()
	case "darwin":
		processes = getProcessesDarwin()
	case "windows":
		processes = getProcessesWindows()
	case "freebsd", "openbsd":
		processes = getProcessesBSD()
	}

	return processes
}

func getProcessesLinux() []models.ProcessInfo {
	var processes []models.ProcessInfo
	entries, err := os.ReadDir("/proc")
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

		// Read process info
		procInfo := models.ProcessInfo{PID: pid}

		// Get command name
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && len(cmdline) > 0 {
			parts := bytes.Split(cmdline, []byte{0})
			if len(parts) > 0 {
				procInfo.Name = filepath.Base(string(parts[0]))
			}
		}

		// Get status info (user, memory)
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(status))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						uid := fields[1]
						if u, err := user.LookupId(uid); err == nil {
							procInfo.User = u.Username
						} else {
							procInfo.User = uid
						}
					}
				} else if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						mem, _ := strconv.ParseUint(fields[1], 10, 64)
						procInfo.Memory = mem * 1024 // Convert KB to bytes
					}
				}
			}
		}

		// Get CPU usage (simplified)
		stat, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err == nil {
			fields := strings.Fields(string(stat))
			if len(fields) > 13 {
				utime, _ := strconv.ParseUint(fields[13], 10, 64)
				stime, _ := strconv.ParseUint(fields[14], 10, 64)
				totalTime := float64(utime + stime)
				procInfo.CPU = totalTime / 100.0 // Simplified CPU percentage
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

func parseProcessesFromPS(args ...string) []models.ProcessInfo {
	var processes []models.ProcessInfo
	cmd := exec.Command("ps", args...)
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

func getProcessesDarwin() []models.ProcessInfo {
	return parseProcessesFromPS("-eo", "pid,user,comm,%cpu,rss")
}

func getProcessesWindows() []models.ProcessInfo {
	var processes []models.ProcessInfo
	cmd := exec.Command("powershell", "-Command",
		"Get-Process | Select-Object -First 100 Id,Name,@{Name='User';Expression={(Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\").GetOwner().User}},CPU,@{Name='Memory';Expression={$_.WorkingSet64}} | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Scan() // Skip header

		for scanner.Scan() {
			line := scanner.Text()
			// Remove quotes and split
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
		cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
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

func getProcessesBSD() []models.ProcessInfo {
	return parseProcessesFromPS("-axo", "pid,user,comm,%cpu,rss")
}

func getServices() []models.ServiceInfo {
	var services []models.ServiceInfo

	switch runtime.GOOS {
	case "linux":
		services = getServicesLinux()
	case "darwin":
		services = getServicesDarwin()
	case "windows":
		services = getServicesWindows()
	case "freebsd":
		services = getServicesFreeBSD()
	case "openbsd":
		services = getServicesOpenBSD()
	}

	return services
}

func getServicesLinux() []models.ServiceInfo {
	var services []models.ServiceInfo

	// Try systemctl first
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
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
	cmd = exec.Command("service", "--status-all")
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

func getServicesDarwin() []models.ServiceInfo {
	var services []models.ServiceInfo
	cmd := exec.Command("launchctl", "list")
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

func getServicesWindows() []models.ServiceInfo {
	var services []models.ServiceInfo
	cmd := exec.Command("powershell", "-Command",
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
		return services
	}

	// Fallback to sc query
	cmd = exec.Command("sc", "query")
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
	return services
}

func getServicesFreeBSD() []models.ServiceInfo {
	var services []models.ServiceInfo
	cmd := exec.Command("service", "-e")
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

func getServicesOpenBSD() []models.ServiceInfo {
	var services []models.ServiceInfo
	cmd := exec.Command("rcctl", "ls", "started")
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
