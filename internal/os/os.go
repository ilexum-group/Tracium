// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ilexum-group/tracium/pkg/models"
)

// DetectOS returns the current operating system
func DetectOS() string {
	return runtime.GOOS
}

// Collector defines the interface for OS-specific information collection
type Collector interface {
	// Embed SystemPrimitives for low-level OS operations
	SystemPrimitives

	// OS primitives
	SetLogger(models.CommandLogger)
	Hostname() (string, error)
	GetCurrentUser() (string, error)
	GetProcessID() int

	// System information
	GetUptime() int64
	GetUsers() []string

	// Hardware information
	GetCPUInfo() models.CPUInfo
	GetMemoryInfo() models.MemoryInfo
	GetDiskInfo() []models.DiskInfo

	// Network information
	GetInterfaces() []models.InterfaceInfo
	GetListeningPorts(seen map[int]bool) []int

	// Security information
	GetProcesses() []models.ProcessInfo
	GetServices() []models.ServiceInfo

	// Forensics methods
	CollectBrowserDBFiles(errors *[]string) []models.ForensicFile
	CollectRecentFiles(errors *[]string) []models.RecentFileEntry
	CollectCommandHistory(errors *[]string) []models.CommandEntry
	CollectNetworkHistory(errors *[]string) models.NetworkHistoryData
	CollectSystemLogs(errors *[]string) []models.LogFile
	CollectScheduledTasks(errors *[]string) []models.ScheduledTask
	CollectActiveConnections(errors *[]string) []models.NetworkConnection
	CollectHostsFile(errors *[]string) *models.ForensicFile
	CollectSSHKeys(errors *[]string) []models.SSHKeyInfo
	CollectInstalledSoftware(errors *[]string) []models.SoftwareInfo
	CollectEnvironmentVariables(errors *[]string) map[string]string
	CollectRecentDownloads(errors *[]string) []models.RecentFileEntry
	CollectUSBHistory(errors *[]string) []models.USBDevice
	CollectPrefetchFiles(errors *[]string) []models.PrefetchInfo
	CollectRecycleBin(errors *[]string) []models.DeletedFile
	CollectClipboard(errors *[]string) string
}

// Default provides default implementations for platform-independent methods
type Default struct {
	logFunc models.CommandLogger
}

// NewDefault creates a new Default instance
func NewDefault() *Default {
	return &Default{}
}

// SetLogger configures the logging function for OS operations
func (d *Default) SetLogger(logFunc models.CommandLogger) {
	d.logFunc = logFunc
}

// Hostname returns the system hostname
func (d *Default) Hostname() (string, error) {
	return os.Hostname()
}

// GetProcessID returns the current process ID
func (d *Default) GetProcessID() int {
	return os.Getpid()
}

// GetCurrentUser retrieves the current executing user (default implementation)
func (d *Default) GetCurrentUser() (string, error) {
	return "unknown", nil
}

// GetInterfaces returns network interfaces (platform-independent using net package)
func (d *Default) GetInterfaces() []models.InterfaceInfo {
	var interfaces []models.InterfaceInfo
	ifaces, err := d.NetInterfaces()
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

// Dummy implementations for methods that must be overridden by platform-specific collectors

// GetUptime returns system uptime (dummy implementation)
func (d *Default) GetUptime() int64 {
	return 0
}

// GetUsers returns list of system users (dummy implementation)
func (d *Default) GetUsers() []string {
	return []string{}
}

// GetCPUInfo returns CPU information (dummy implementation)
func (d *Default) GetCPUInfo() models.CPUInfo {
	return models.CPUInfo{}
}

// GetMemoryInfo returns memory information (dummy implementation)
func (d *Default) GetMemoryInfo() models.MemoryInfo {
	return models.MemoryInfo{}
}

// GetDiskInfo returns disk information (dummy implementation)
func (d *Default) GetDiskInfo() []models.DiskInfo {
	return []models.DiskInfo{}
}

// GetListeningPorts returns listening ports (dummy implementation)
func (d *Default) GetListeningPorts(_ map[int]bool) []int {
	return []int{}
}

// GetProcesses returns running processes (dummy implementation)
func (d *Default) GetProcesses() []models.ProcessInfo {
	return []models.ProcessInfo{}
}

// GetServices returns system services (dummy implementation)
func (d *Default) GetServices() []models.ServiceInfo {
	return []models.ServiceInfo{}
}

// CollectBrowserDBFiles collects browser database files (dummy implementation)
func (d *Default) CollectBrowserDBFiles(_ *[]string) []models.ForensicFile {
	return []models.ForensicFile{}
}

// CollectRecentFiles collects recently accessed files (dummy implementation)
func (d *Default) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	return []models.RecentFileEntry{}
}

// CollectCommandHistory collects shell command history (dummy implementation)
func (d *Default) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	return []models.CommandEntry{}
}

// CollectNetworkHistory collects network connection history (dummy implementation)
func (d *Default) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	return models.NetworkHistoryData{}
}

// CollectSystemLogs collects system log files (dummy implementation)
func (d *Default) CollectSystemLogs(_ *[]string) []models.LogFile {
	return []models.LogFile{}
}

// CollectScheduledTasks collects scheduled tasks (dummy implementation)
func (d *Default) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	return []models.ScheduledTask{}
}

// CollectActiveConnections collects active network connections (dummy implementation)
func (d *Default) CollectActiveConnections(_ *[]string) []models.NetworkConnection {
	return []models.NetworkConnection{}
}

// CollectHostsFile collects the hosts file (dummy implementation)
func (d *Default) CollectHostsFile(_ *[]string) *models.ForensicFile {
	return nil
}

// CollectSSHKeys collects SSH key information (dummy implementation)
func (d *Default) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return []models.SSHKeyInfo{}
}

// CollectInstalledSoftware collects installed software information (dummy implementation)
func (d *Default) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	return []models.SoftwareInfo{}
}

// CollectEnvironmentVariables collects environment variables (dummy implementation)
func (d *Default) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return map[string]string{}
}

// CollectRecentDownloads collects recently downloaded files (dummy implementation)
func (d *Default) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return []models.RecentFileEntry{}
}

// CollectUSBHistory collects USB device connection history (dummy implementation)
func (d *Default) CollectUSBHistory(_ *[]string) []models.USBDevice {
	return []models.USBDevice{}
}

// CollectPrefetchFiles collects Windows prefetch files (dummy implementation)
func (d *Default) CollectPrefetchFiles(_ *[]string) []models.PrefetchInfo {
	return []models.PrefetchInfo{}
}

// CollectRecycleBin collects recycle bin contents (dummy implementation)
func (d *Default) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	return []models.DeletedFile{}
}

// CollectClipboard collects current clipboard content (dummy implementation)
func (d *Default) CollectClipboard(_ *[]string) string {
	return ""
}

// Shared forensics helper methods in Default

// CopyFileArtifact copies a file if it exists and returns its metadata
func (d *Default) CopyFileArtifact(src, prefix, browser string) (*models.ForensicFile, error) {
	if _, err := d.OSStat(src); err != nil {
		return nil, fmt.Errorf("artifact missing: %s", src)
	}

	dest := filepath.Join(os.TempDir(), fmt.Sprintf("%s_%d.db", prefix, time.Now().UnixNano()))

	//nolint:gosec // G304: src is from trusted forensics collection sources
	sourceFile, err := d.OSOpen(src)
	if err != nil {
		return nil, fmt.Errorf("copy failed for %s: %w", src, err)
	}
	defer func() {
		_ = sourceFile.Close() // Explicitly ignore error
	}()

	//nolint:gosec // G304: dest is controlled output path
	destFile, err := d.OSCreate(dest)
	if err != nil {
		return nil, fmt.Errorf("copy failed for %s: %w", src, err)
	}
	defer func() {
		_ = destFile.Close() // Explicitly ignore error
	}()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destFile, hasher), sourceFile)
	if err != nil {
		return nil, fmt.Errorf("copy failed for %s: %w", src, err)
	}

	return &models.ForensicFile{
		Name:     filepath.Base(src),
		Path:     dest,
		Size:     written,
		Hash:     fmt.Sprintf("%x", hasher.Sum(nil)),
		Category: "browser_db",
		Browser:  browser,
	}, nil
}

// ReadFileWithLimit reads a file up to maxSize bytes and returns base64 encoded content
func (d *Default) ReadFileWithLimit(path string, maxSize int64) (string, bool, error) {
	info, err := d.OSStat(path)
	if err != nil {
		return "", false, err
	}

	//nolint:gosec // G304: path is from trusted forensics collection sources
	file, err := d.OSOpen(path)
	if err != nil {
		return "", false, err
	}
	defer func() {
		_ = file.Close() // Explicitly ignore error
	}()

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

// CollectARPCacheUnix collects ARP cache on Unix-like systems
func (d *Default) CollectARPCacheUnix() []models.ARPEntry {
	entries := make([]models.ARPEntry, 0)

	output, err := d.ExecCommand("arp", "-n").Output()
	if err != nil {
		return entries
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Address") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			entries = append(entries, models.ARPEntry{
				IPAddress:  fields[0],
				MACAddress: fields[2],
				Type:       "dynamic",
			})
		}
	}

	return entries
}

// CollectNetstatConnections collects active connections using netstat
func (d *Default) CollectNetstatConnections(platform string, errors *[]string) []models.NetworkConnection {
	connections := make([]models.NetworkConnection, 0)

	var cmd *exec.Cmd
	if platform == "windows" {
		cmd = d.ExecCommand("netstat", "-ano")
	} else {
		cmd = d.ExecCommand("netstat", "-antp")
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

		if strings.Contains(fields[1], ":") {
			parts := strings.Split(fields[1], ":")
			conn.LocalAddress = parts[0]
			if len(parts) > 1 {
				port, _ := strconv.Atoi(parts[len(parts)-1])
				conn.LocalPort = port
			}
		}

		if len(fields) > 2 && strings.Contains(fields[2], ":") {
			parts := strings.Split(fields[2], ":")
			conn.RemoteAddress = parts[0]
			if len(parts) > 1 {
				port, _ := strconv.Atoi(parts[len(parts)-1])
				conn.RemotePort = port
			}
		}

		if len(fields) > 3 {
			conn.State = fields[3]
		}

		if platform == "windows" && len(fields) > 4 {
			pid, _ := strconv.Atoi(fields[len(fields)-1])
			conn.PID = pid
		}

		connections = append(connections, conn)
	}

	return connections
}

// CollectHostsFileCommon collects hosts file across platforms
func (d *Default) CollectHostsFileCommon(hostsPath string, errors *[]string) *models.ForensicFile {
	info, err := d.OSStat(hostsPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("hosts file not found: %v", err))
		}
		return nil
	}

	content, _, err := d.ReadFileWithLimit(hostsPath, 1024*1024)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to read hosts file: %v", err))
		}
		return nil
	}

	//nolint:gosec // G304: hostsPath is trusted system file path
	data, err := d.OSReadFile(hostsPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to hash hosts file: %v", err))
		}
		return nil
	}

	hasher := sha256.New()
	hasher.Write(data)

	return &models.ForensicFile{
		Name:     "hosts",
		Path:     hostsPath,
		Size:     info.Size(),
		Hash:     fmt.Sprintf("%x", hasher.Sum(nil)),
		Category: "system_config",
		Data:     content,
	}
}

// CollectSSHKeysCommon collects SSH keys across Unix-like platforms
func (d *Default) CollectSSHKeysCommon() []models.SSHKeyInfo {
	keys := make([]models.SSHKeyInfo, 0)

	homeDir, err := d.OSUserHomeDir()
	if err != nil {
		return keys
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if _, err := d.OSStat(sshDir); err != nil {
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
		info, err := d.OSStat(keyPath)
		if err != nil {
			continue
		}

		keyInfo := models.SSHKeyInfo{
			Path: keyPath,
			Type: kf.typ,
			Size: info.Size(),
		}

		if info.Size() < 100*1024 {
			content, _, err := d.ReadFileWithLimit(keyPath, 100*1024)
			if err == nil {
				keyInfo.Content = content
			}
		}

		keys = append(keys, keyInfo)
	}

	return keys
}

// CollectEnvironmentVariablesCommon collects environment variables
func (d *Default) CollectEnvironmentVariablesCommon() map[string]string {
	envVars := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}
	return envVars
}

// CollectDownloadsCommon collects recent downloads from Downloads folder
func (d *Default) CollectDownloadsCommon(additionalPaths []string) []models.RecentFileEntry {
	downloads := make([]models.RecentFileEntry, 0)
	homeDir, err := d.OSUserHomeDir()
	if err != nil {
		return downloads
	}

	downloadPaths := []string{filepath.Join(homeDir, "Downloads")}
	downloadPaths = append(downloadPaths, additionalPaths...)

	for _, downloadPath := range downloadPaths {
		entries, err := d.OSReadDir(downloadPath)
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

	return downloads
}

// New returns the appropriate OS collector based on the runtime OS
func New() Collector {
	switch runtime.GOOS {
	case "linux":
		return NewLinux()
	case "darwin":
		return NewDarwin()
	case "windows":
		return NewWindows()
	case "freebsd":
		return NewFreeBSD()
	case "openbsd":
		return NewOpenBSD()
	default:
		return NewDefault() // Default fallback
	}
}
