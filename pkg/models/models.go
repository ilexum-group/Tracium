// Package models defines data structures for system information collected by the agent
package models

// SystemData represents the complete data collected by the agent
type SystemData struct {
	CaseID       string             `json:"case_id"` // Case identifier for correlation
	System       SystemInfo         `json:"system"`
	Hardware     HardwareInfo       `json:"hardware"`
	Network      NetworkInfo        `json:"network"`
	Security     SecurityInfo       `json:"security"`
	Forensics    ForensicsData      `json:"forensics"`
	Tree         FilesystemTree     `json:"tree"`
	CustodyChain *CustodyChainEntry `json:"custody_chain"` // Custody Chain - Complete digital evidence custody tracking
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

// BrowserArtifacts represents structured browser artifacts collected from the system
type BrowserArtifacts struct {
	ChromiumProfiles   []ForensicFile `json:"chromium_profiles,omitempty"`
	ChromiumExtensions []ForensicFile `json:"chromium_extensions,omitempty"`
	Bookmarks          []ForensicFile `json:"bookmarks,omitempty"`
	Cache              []ForensicFile `json:"cache,omitempty"`
	Cookies            []ForensicFile `json:"cookies,omitempty"`
	Downloads          []ForensicFile `json:"downloads,omitempty"`
	FormAutofill       []ForensicFile `json:"form_autofill,omitempty"`
	History            []ForensicFile `json:"history,omitempty"`
	SearchHistory      []ForensicFile `json:"search_history,omitempty"`
}

// GmailFolders represents Gmail-specific folder structures
type GmailFolders struct {
	Drafts []ForensicFile `json:"drafts,omitempty"`
	Sent   []ForensicFile `json:"sent,omitempty"`
	Trash  []ForensicFile `json:"trash,omitempty"`
}

// EmailArtifacts represents email artifacts (generic and Gmail-specific)
type EmailArtifacts struct {
	Default []ForensicFile `json:"default,omitempty"`
	Gmail   GmailFolders   `json:"gmail,omitempty"`
}

// CommunicationArtifacts represents communication artifacts (email accounts, messages)
type CommunicationArtifacts struct {
	Accounts []ForensicFile `json:"accounts,omitempty"`
	Emails   EmailArtifacts `json:"emails,omitempty"`
}

// ForensicsData holds forensic artifacts collected from the system
type ForensicsData struct {
	RecentFiles       []RecentFileEntry   `json:"recent_files"`
	CommandHistory    []CommandEntry      `json:"command_history"`
	NetworkHistory    NetworkHistoryData  `json:"network_history"`
	Browser           BrowserArtifacts    `json:"browser,omitempty"`
	Communication     CommunicationArtifacts `json:"communication,omitempty"`
	SystemLogs        []LogFile           `json:"system_logs,omitempty"`
	ScheduledTasks    []ScheduledTask     `json:"scheduled_tasks,omitempty"`
	ActiveConnections []NetworkConnection `json:"active_connections,omitempty"`
	HostsFile         *ForensicFile       `json:"hosts_file,omitempty"`
	SSHKeys           []SSHKeyInfo        `json:"ssh_keys,omitempty"`
	InstalledSoftware []SoftwareInfo      `json:"installed_software,omitempty"`
	EnvironmentVars   map[string]string   `json:"environment_vars,omitempty"`
	RecentDownloads   []RecentFileEntry   `json:"recent_downloads,omitempty"`
	USBHistory        []USBDevice         `json:"usb_history,omitempty"`
	PrefetchFiles     []PrefetchInfo      `json:"prefetch_files,omitempty"`
	RecycleBin        []DeletedFile       `json:"recycle_bin,omitempty"`
	ClipboardContent  string              `json:"clipboard_content,omitempty"`
	CollectionErrors  []string            `json:"collection_errors,omitempty"`
}

// FilesystemTree represents the full filesystem tree of the analyzed system.
type FilesystemTree struct {
	Nodes []TreeNode `json:"nodes"`
}

// TreeNode represents a file or directory in the filesystem tree.
type TreeNode struct {
	Path         string `json:"path"`
	Name         string `json:"name"`
	Parent       string `json:"parent"`
	Type         string `json:"type"` // file, directory, symlink
	Size         int64  `json:"size"`
	Deleted      bool   `json:"deleted,omitempty"`
	Permissions  string `json:"permissions,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Group        string `json:"group,omitempty"`
	Inode        uint64 `json:"inode,omitempty"`
	AccessedTime int64  `json:"accessed_time,omitempty"`
	ModifiedTime int64  `json:"modified_time,omitempty"`
	CreatedTime  int64  `json:"created_time,omitempty"`
}

// ForensicFile represents a collected artifact file (e.g., browser DB)
type ForensicFile struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	Category string `json:"category"` // e.g., browser_db
	Browser  string `json:"browser,omitempty"`
	Data     string `json:"data,omitempty"` // Base64 encoded file content
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

// LogFile represents a system log file
type LogFile struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Content   string `json:"content,omitempty"` // Last N lines or full content if small
	Truncated bool   `json:"truncated"`
}

// ScheduledTask represents a scheduled task or cron job
type ScheduledTask struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Schedule    string `json:"schedule"`
	User        string `json:"user"`
	Enabled     bool   `json:"enabled"`
	Source      string `json:"source"` // cron, systemd, windows_task, etc.
	Description string `json:"description,omitempty"`
}

// NetworkConnection represents an active network connection
type NetworkConnection struct {
	Protocol      string `json:"protocol"` // TCP, UDP
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	State         string `json:"state"` // ESTABLISHED, LISTEN, etc.
	PID           int    `json:"pid,omitempty"`
	ProcessName   string `json:"process_name,omitempty"`
}

// SSHKeyInfo represents SSH key information
type SSHKeyInfo struct {
	Path        string `json:"path"`
	Type        string `json:"type"` // authorized_keys, known_hosts, private_key, public_key
	Fingerprint string `json:"fingerprint,omitempty"`
	Size        int64  `json:"size"`
	Content     string `json:"content,omitempty"` // Base64 for small files
}

// SoftwareInfo represents installed software
type SoftwareInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	Source      string `json:"source"` // registry, apt, yum, brew, etc.
}

// USBDevice represents USB device connection history
type USBDevice struct {
	DeviceID     string `json:"device_id"`
	VendorID     string `json:"vendor_id,omitempty"`
	ProductID    string `json:"product_id,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Description  string `json:"description,omitempty"`
	FirstSeen    string `json:"first_seen,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"`
}

// PrefetchInfo represents Windows prefetch file information
type PrefetchInfo struct {
	FileName    string `json:"file_name"`
	Executable  string `json:"executable"`
	RunCount    int    `json:"run_count,omitempty"`
	LastRunTime int64  `json:"last_run_time,omitempty"`
	FilesLoaded int    `json:"files_loaded,omitempty"`
}

// DeletedFile represents a file in recycle bin
type DeletedFile struct {
	OriginalPath string `json:"original_path"`
	DeletedPath  string `json:"deleted_path"`
	FileName     string `json:"file_name"`
	Size         int64  `json:"size"`
	DeletedTime  int64  `json:"deleted_time,omitempty"`
}
