// Package models defines data structures for system information collected by the agent
package models

// SystemData represents the complete data collected by the agent
type SystemData struct {
	Timestamp  int64         `json:"timestamp"`
	System     SystemInfo    `json:"system"`
	Hardware   HardwareInfo  `json:"hardware"`
	Network    NetworkInfo   `json:"network"`
	Security   SecurityInfo  `json:"security"`
	DiskImages []DiskImage   `json:"disk_images"`
	Logs       []string      `json:"logs"`
	Forensics  ForensicsData `json:"forensics"`
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

// DiskImage holds disk imaging information
type DiskImage struct {
	DiskPath    string `json:"disk_path"`
	ImagePath   string `json:"image_path"`
	ImageHash   string `json:"image_hash"`
	ImageSize   uint64 `json:"image_size"`
	Status      string `json:"status"`
	Timestamp   int64  `json:"timestamp"`
	Description string `json:"description"`
}

// ForensicsData holds forensic artifacts collected from the system
type ForensicsData struct {
	BrowserHistory   []BrowserHistoryEntry `json:"browser_history"`
	Cookies          []CookieEntry         `json:"cookies"`
	RecentFiles      []RecentFileEntry     `json:"recent_files"`
	CommandHistory   []CommandEntry        `json:"command_history"`
	Downloads        []DownloadEntry       `json:"downloads"`
	NetworkHistory   NetworkHistoryData    `json:"network_history"`
	CollectionErrors []string              `json:"collection_errors,omitempty"`
}

// BrowserHistoryEntry represents a browser history entry
type BrowserHistoryEntry struct {
	Browser       string `json:"browser"` // chrome, firefox, edge, safari
	URL           string `json:"url"`
	Title         string `json:"title"`
	VisitCount    int    `json:"visit_count"`
	LastVisitTime int64  `json:"last_visit_time"` // Unix timestamp
	Typed         bool   `json:"typed,omitempty"`
}

// CookieEntry represents a browser cookie
type CookieEntry struct {
	Browser      string `json:"browser"`
	Host         string `json:"host"`
	Name         string `json:"name"`
	Value        string `json:"value,omitempty"` // May be encrypted
	Path         string `json:"path"`
	ExpiresTime  int64  `json:"expires_time"` // Unix timestamp
	Secure       bool   `json:"secure"`
	HTTPOnly     bool   `json:"http_only"`
	CreationTime int64  `json:"creation_time"` // Unix timestamp
}

// RecentFileEntry represents a recently accessed file
type RecentFileEntry struct {
	FilePath     string `json:"file_path"`
	FileName     string `json:"file_name"`
	AccessedTime int64  `json:"accessed_time"` // Unix timestamp
	Source       string `json:"source"`        // windows_recent, jumplist, xbel, etc.
}

// CommandEntry represents a shell command history entry
type CommandEntry struct {
	Shell     string `json:"shell"` // bash, powershell, zsh, cmd
	Command   string `json:"command"`
	Timestamp int64  `json:"timestamp"` // Unix timestamp (if available)
	LineNum   int    `json:"line_num"`  // Line number in history file
}

// DownloadEntry represents a downloaded file
type DownloadEntry struct {
	Browser    string `json:"browser,omitempty"`
	FilePath   string `json:"file_path"`
	URL        string `json:"url,omitempty"`
	StartTime  int64  `json:"start_time"` // Unix timestamp
	EndTime    int64  `json:"end_time"`   // Unix timestamp
	BytesTotal int64  `json:"bytes_total"`
	State      string `json:"state"` // complete, interrupted, cancelled
	DangerType string `json:"danger_type,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
}

// NetworkHistoryData holds network connection history
type NetworkHistoryData struct {
	ARPCache []ARPEntry `json:"arp_cache"`
	DNSCache []DNSEntry `json:"dns_cache"`
}

// ARPEntry represents an ARP cache entry
type ARPEntry struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Interface  string `json:"interface,omitempty"`
	Type       string `json:"type"` // dynamic, static
}

// DNSEntry represents a DNS cache entry
type DNSEntry struct {
	Hostname   string   `json:"hostname"`
	IPAddress  []string `json:"ip_address"`
	RecordType string   `json:"record_type"` // A, AAAA, CNAME, etc.
	TTL        int      `json:"ttl"`
}
