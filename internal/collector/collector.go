package collector

import (
	"net"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/tracium/internal/models"
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

// Placeholder implementations - in a real implementation, use libraries like gopsutil

func getUsers() []string {
	var users []string
	userList, err := user.Current()
	if err == nil {
		users = append(users, userList.Username)
	}
	return users
}

func getUptime() int64 {
	// Placeholder - in real implementation, calculate actual uptime
	return time.Now().Unix() - 1000000 // Mock value
}

func getCPUInfo() models.CPUInfo {
	return models.CPUInfo{
		Model: "Intel Core i7", // Placeholder
		Cores: runtime.NumCPU(),
	}
}

func getMemoryInfo() models.MemoryInfo {
	return models.MemoryInfo{
		Total: 16 * 1024 * 1024 * 1024, // 16GB placeholder
		Used:  8 * 1024 * 1024 * 1024,  // 8GB placeholder
	}
}

func getDiskInfo() []models.DiskInfo {
	// Placeholder - in real implementation, enumerate partitions
	return []models.DiskInfo{
		{
			Path:       "/",
			Total:      500 * 1024 * 1024 * 1024, // 500GB
			Used:       200 * 1024 * 1024 * 1024, // 200GB
			FileSystem: "ext4",
		},
	}
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
	// Placeholder - in real implementation, use netstat or similar
	return []int{22, 80, 443} // SSH, HTTP, HTTPS
}

func getProcesses() []models.ProcessInfo {
	// Placeholder - in real implementation, enumerate processes
	return []models.ProcessInfo{
		{PID: 1, Name: "init", User: "root", CPU: 0.1, Memory: 1024},
	}
}

func getServices() []models.ServiceInfo {
	// Placeholder - in real implementation, enumerate services based on OS
	if runtime.GOOS == "linux" {
		return []models.ServiceInfo{
			{Name: "sshd", Status: "running", Description: "OpenSSH server"},
		}
	}
	return []models.ServiceInfo{}
}
