// Package models defines data structures for system information collected by the agent
package models

// SystemData represents the complete data collected by the agent
type SystemData struct {
	Timestamp int64        `json:"timestamp"`
	System    SystemInfo   `json:"system"`
	Hardware  HardwareInfo `json:"hardware"`
	Network   NetworkInfo  `json:"network"`
	Security  SecurityInfo `json:"security"`
}

// SystemInfo holds basic system information
type SystemInfo struct {
	OS           string   `json:"os"`
	Hostname     string   `json:"hostname"`
	Architecture string   `json:"architecture"`
	Uptime       int64    `json:"uptime"`
	Users        []string `json:"users"`
}

// HardwareInfo holds hardware-related information
type HardwareInfo struct {
	CPU    CPUInfo    `json:"cpu"`
	Memory MemoryInfo `json:"memory"`
	Disk   []DiskInfo `json:"disk"`
}

// CPUInfo holds CPU information
type CPUInfo struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
}

// MemoryInfo holds memory information
type MemoryInfo struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

// DiskInfo holds disk partition information
type DiskInfo struct {
	Path       string `json:"path"`
	Total      uint64 `json:"total"`
	Used       uint64 `json:"used"`
	FileSystem string `json:"filesystem"`
}

// NetworkInfo holds network information
type NetworkInfo struct {
	Interfaces     []InterfaceInfo `json:"interfaces"`
	ListeningPorts []int           `json:"listening_ports"`
}

// InterfaceInfo holds network interface information
type InterfaceInfo struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
	MAC  string   `json:"mac"`
}

// SecurityInfo holds security-related information
type SecurityInfo struct {
	Processes []ProcessInfo `json:"processes"`
	Services  []ServiceInfo `json:"services"`
}

// ProcessInfo holds process information
type ProcessInfo struct {
	PID    int     `json:"pid"`
	Name   string  `json:"name"`
	User   string  `json:"user"`
	CPU    float64 `json:"cpu"`
	Memory uint64  `json:"memory"`
}

// ServiceInfo holds service information
type ServiceInfo struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Description string `json:"description"`
}
