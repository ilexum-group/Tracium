// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

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
	OSName() string
	Architecture() string
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
	CollectBrowserArtifacts(errors *[]string) models.BrowserArtifacts
	CollectCommunicationArtifacts(errors *[]string) models.CommunicationArtifacts
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
	CollectFilesystemTree() models.FilesystemTree
}

// Default provides default implementations for platform-independent methods
type Default struct {
	logFunc      models.CommandLogger
	mode         AnalysisMode
	fileAccessor FileAccessor
	osName       string
	arch         string
}

// NewDefault creates a new Default instance
func NewDefault() *Default {
	return &Default{
		mode:         LiveMode,
		fileAccessor: newHostFileAccessor(),
	}
}

// NewDefaultWithOptions creates a Default configured for the provided options.
func NewDefaultWithOptions(opts CollectorOptions) (*Default, error) {
	if opts.ImagePath == "" {
		return NewDefault(), nil
	}

	accessor, err := newImageFileAccessor(opts.ImagePath)
	if err != nil {
		return nil, err
	}

	return &Default{
		mode:         ImageMode,
		fileAccessor: accessor,
	}, nil
}

// IsLive returns true when running in live analysis mode.
func (d *Default) IsLive() bool {
	return d.mode == LiveMode
}

// OSName returns the detected OS name.
func (d *Default) OSName() string {
	if d.osName != "" {
		return d.osName
	}
	return runtime.GOOS
}

// Architecture returns the detected CPU architecture.
func (d *Default) Architecture() string {
	if d.arch != "" {
		return d.arch
	}
	if d.IsLive() {
		return runtime.GOARCH
	}
	return "unknown"
}

// SetLogger configures the logging function for OS operations
func (d *Default) SetLogger(logFunc models.CommandLogger) {
	d.logFunc = logFunc
}

// Hostname returns the system hostname
func (d *Default) Hostname() (string, error) {
	if data, err := d.OSReadFile("/etc/hostname"); err == nil {
		name := strings.TrimSpace(string(data))
		if name != "" {
			return name, nil
		}
	}
	if !d.IsLive() {
		return "", fmt.Errorf("hostname unavailable in post-mortem mode")
	}
	return os.Hostname()
}

// GetProcessID returns the current process ID
func (d *Default) GetProcessID() int {
	if !d.IsLive() {
		return 0
	}
	return os.Getpid()
}

// GetCurrentUser retrieves the current executing user (default implementation)
func (d *Default) GetCurrentUser() (string, error) {
	return "unknown", nil
}

// GetInterfaces returns network interfaces (platform-independent using net package)
func (d *Default) GetInterfaces() []models.InterfaceInfo {
	var interfaces []models.InterfaceInfo
	if !d.IsLive() {
		return interfaces
	}
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

func (d *Default) collectFilesystemTreeImage() models.FilesystemTree {
	accessor, ok := d.fileAccessor.(*imageFileAccessor)
	if !ok {
		return models.FilesystemTree{Nodes: []models.TreeNode{}}
	}

	// Incluye archivos borrados y no borrados
	cmd := d.ExecCommand("fls", "-r", "-p", "-o", strconv.FormatInt(accessor.offset, 10), accessor.imagePath)
	fmt.Printf("[os] collectFilesystemTreeImage: running command: %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[os] collectFilesystemTreeImage: fls error: %v\n", err)
		return models.FilesystemTree{Nodes: []models.TreeNode{}}
	}
	fmt.Printf("[os] collectFilesystemTreeImage: fls output size=%d bytes\n", len(output))

	nodes := parseFlsOutput(output)
	deletedCount := 0
	for _, n := range nodes {
		if n.Deleted {
			deletedCount++
		}
	}
	fmt.Printf("[os] collectFilesystemTreeImage: parsed %d nodes (%d deleted)\n", len(nodes), deletedCount)

	return models.FilesystemTree{
		Nodes: nodes,
	}
}

// CollectFilesystemTree collects filesystem tree for Default (fallback implementation)
func (d *Default) CollectFilesystemTree() models.FilesystemTree {
	if d.IsLive() {
		return models.FilesystemTree{Nodes: d.collectTreeWithTreeCommand()}
	}
	return d.collectFilesystemTreeImage()
}

func (d *Default) collectTreeWithTreeCommand() []models.TreeNode {
	root := d.treeRoots()
	rootPath := "/"
	if len(root) > 0 {
		rootPath = root[0]
	}
	cmd := d.ExecCommand("tree", "-a", "-f", "-i", "-n", rootPath)
	output, err := cmd.Output()
	if err != nil {
		return []models.TreeNode{}
	}

	nodes := make([]models.TreeNode, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "directories,") {
			continue
		}
		p := strings.TrimSpace(line)
		nodes = append(nodes, models.TreeNode{
			Path:   p,
			Name:   filepath.Base(p),
			Parent: parentPath(p),
			Type:   "file",
		})
	}
	return nodes
}

func (d *Default) treeRoots() []string {
	if d.OSName() == "windows" {
		if d.IsLive() {
			base := d.OSGetenv("SystemDrive")
			if base == "" {
				base = "C:"
			}
			return []string{base + "\\"}
		}
		return []string{"C:\\"}
	}
	return []string{"/"}
}

func buildTreeNode(path, parent string, info os.FileInfo) models.TreeNode {
	typeLabel := "file"
	if info.IsDir() {
		typeLabel = "directory"
	} else if info.Mode()&os.ModeSymlink != 0 {
		typeLabel = "symlink"
	}
	return models.TreeNode{
		Path:         path,
		Name:         info.Name(),
		Parent:       parent,
		Type:         typeLabel,
		Size:         info.Size(),
		Permissions:  info.Mode().Perm().String(),
		ModifiedTime: info.ModTime().Unix(),
	}
}

func parseFlsOutput(output []byte) []models.TreeNode {
	nodes := make([]models.TreeNode, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		deleted := false
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.TrimSpace(parts[0])
		pathStr := strings.TrimSpace(parts[1])
		fields := strings.Fields(left)
		inode := uint64(0)

		for _, f := range fields {
			if f == "*" {
				deleted = true
				if strings.Contains(pathStr, "Users") {
					fmt.Printf("path deleted = %s\n", pathStr)
				}
				continue
			}
			if n, err := strconv.ParseUint(f, 10, 64); err == nil {
				inode = n
			}
		}

		if len(fields) > 0 {
			if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
				inode = v
			}
		}
		fileType := "file"
		if strings.HasPrefix(left, "d/") {
			fileType = "directory"
		} else if strings.HasPrefix(left, "l/") {
			fileType = "symlink"
		}
		nodes = append(nodes, models.TreeNode{
			Path:    pathStr,
			Name:    filepath.Base(pathStr),
			Parent:  parentPath(pathStr),
			Type:    fileType,
			Inode:   inode,
			Deleted: deleted,
		})
	}
	return nodes
}

func parseInt64(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	v, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		return v
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

func parseFloatTime(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

func parseTimeToUnix(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts.Unix()
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts.Unix()
	}
	if ts, err := time.Parse("1/2/2006 3:04:05 PM", value); err == nil {
		return ts.Unix()
	}
	return 0
}

func parentPath(p string) string {
	if strings.Contains(p, "/") && !strings.Contains(p, "\\") {
		return path.Dir(p)
	}
	return filepath.Dir(p)
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

	if data, err := d.OSReadFile("/proc/net/arp"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Scan() // Skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				entries = append(entries, models.ARPEntry{
					IPAddress:  fields[0],
					MACAddress: fields[3],
					Type:       "dynamic",
				})
			}
		}
		return entries
	}

	if !d.IsLive() {
		return entries
	}

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
	if !d.IsLive() {
		return connections
	}

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
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
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

	for _, homeDir := range homeDirs {
		sshDir := filepath.Join(homeDir, ".ssh")
		if _, err := d.OSStat(sshDir); err != nil {
			continue
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
	}

	return keys
}

// CollectEnvironmentVariablesCommon collects environment variables
func (d *Default) CollectEnvironmentVariablesCommon() map[string]string {
	envVars := make(map[string]string)
	if !d.IsLive() {
		return envVars
	}
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
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		return downloads
	}

	downloadPaths := make([]string, 0, len(homeDirs)+len(additionalPaths))
	for _, homeDir := range homeDirs {
		downloadPaths = append(downloadPaths, filepath.Join(homeDir, "Downloads"))
	}
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

func (d *Default) resolveImageUserHomeDir() (string, error) {
	homes, err := d.resolveImageUserHomeDirs()
	if err != nil || len(homes) == 0 {
		fmt.Printf("[os] resolveImageUserHomeDir: no user home found, returning /\n")
		return "/", fmt.Errorf("no user home directory found in image")
	}
	fmt.Printf("[os] resolveImageUserHomeDir: selected=%s\n", homes[0])
	return homes[0], nil
}

func (d *Default) resolveImageUserHomeDirs() ([]string, error) {
	preferred := []string{`/home`, `/Users`}
	if d.OSName() == "windows" {
		preferred = []string{`C:\\Users`}
	}
	fmt.Printf("[os] resolveImageUserHomeDirs: os=%s preferred=%v\n", d.OSName(), preferred)

	users := make([]string, 0)
	seen := make(map[string]bool)
	for _, base := range preferred {
		entries, err := d.OSReadDir(base)
		if err != nil {
			fmt.Printf("[os] resolveImageUserHomeDirs: read dir failed: %s err=%v\n", base, err)
			continue
		}
		fmt.Printf("[os] resolveImageUserHomeDirs: base=%s entries=%d\n", base, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if name == "Default" || name == "Default User" || name == "All Users" || name == "Public" {
				continue
			}
			resolved := filepath.Join(base, name)
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			users = append(users, resolved)
		}
	}

	if len(users) == 0 {
		fmt.Printf("[os] resolveImageUserHomeDirs: no user homes found\n")
		return nil, fmt.Errorf("no user home directory found in image")
	}
	return users, nil
}

// DetectOSFromImage determines OS based on filesystem artifacts in an image.
func DetectOSFromImage(accessor *Default) string {
	checks := []struct {
		path string
		os   string
	}{
		{"/Windows/System32/config/SYSTEM", "windows"},
		{"/System/Library/CoreServices/SystemVersion.plist", "darwin"},
		{"/etc/os-release", "linux"},
		{"/etc/lsb-release", "linux"},
		{"/etc/freebsd-update.conf", "freebsd"},
		{"/etc/openbsd-release", "openbsd"},
	}

	for _, c := range checks {
		if _, err := accessor.OSStat(c.path); err == nil {
			return c.os
		}
	}

	return "unknown"
}

// NewWithOptions returns a collector configured for live or image analysis.
func NewWithOptions(opts CollectorOptions) (Collector, error) {
	if opts.ImagePath == "" {
		return New(), nil
	}

	def, err := NewDefaultWithOptions(opts)
	if err != nil {
		return nil, err
	}

	def.osName = DetectOSFromImage(def)
	def.arch = "unknown"

	return newCollectorForOS(def.osName, def), nil
}

func newCollectorForOS(osName string, def *Default) Collector {
	switch osName {
	case "linux":
		return NewLinuxWithDefault(def)
	case "darwin":
		return NewDarwinWithDefault(def)
	case "windows":
		return NewWindowsWithDefault(def)
	case "freebsd":
		return NewFreeBSDWithDefault(def)
	case "openbsd":
		return NewOpenBSDWithDefault(def)
	default:
		return def
	}
}

// New returns the appropriate OS collector based on the runtime OS
func New() Collector {
	return newCollectorForOS(runtime.GOOS, NewDefault())
}

// =============================================================================
// Structured Artifact Collection Implementation
// =============================================================================

// ChromeHistorySQL is the query to extract Chrome/Edge history
const ChromeHistorySQL = `
	SELECT url, title, visit_count, visit_duration, from_visit, is_indexed,
		   visit_time, last_visit_time, hidden
	FROM urls
	ORDER BY last_visit_time DESC
	LIMIT 10000
`

// ChromeDownloadSQL is the query to extract Chrome/Edge downloads
const ChromeDownloadSQL = `
	SELECT target_path, url, start_time, end_time, received_bytes, total_bytes,
		   mime_type, danger_type, opened, interrupt_reason, last_modified
	FROM downloads
	ORDER BY start_time DESC
	LIMIT 5000
`

// ChromeCookieSQL is the query to extract Chrome/Edge cookies
const ChromeCookieSQL = `
	SELECT host_key, name, value, path, creation_utc, expires_utc,
		   last_access_utc, is_secure, is_httponly, same_site, priority
	FROM cookies
	ORDER BY creation_utc DESC
	LIMIT 10000
`

// ChromeAutofillSQL is the query to extract Chrome/Edge form autofill
const ChromeAutofillSQL = `
	SELECT name, value, count, date_created, usage_count
	FROM autofill
	ORDER BY date_created DESC
	LIMIT 5000
`

// FirefoxHistorySQL is the query to extract Firefox history
const FirefoxHistorySQL = `
	SELECT p.url, p.title, h.visit_date, h.visit_type, h.from_visit
	FROM moz_places p
	JOIN moz_historyvisits h ON p.id = h.place_id
	ORDER BY h.visit_date DESC
	LIMIT 10000
`

// FirefoxCookieSQL is the query to extract Firefox cookies
const FirefoxCookieSQL = `
	SELECT host, name, value, path, creationTime, expirationDate,
		   lastAccessTime, isSecure, isHttpOnly, baseDomain
	FROM moz_cookies
	ORDER BY creationTime DESC
	LIMIT 10000
`

// FirefoxBookmarksSQL is the query to extract Firefox bookmarks
const FirefoxBookmarksSQL = `
	SELECT b.title, p.url, b.dateAdded, b.lastModified, b.position,
		   b.type, p.visit_count
	FROM moz_bookmarks b
	JOIN moz_places p ON b.fk = p.id
	ORDER BY b.dateAdded DESC
	LIMIT 5000
`

// FirefoxSearchSQL is the query to extract Firefox search history
const FirefoxSearchSQL = `
	SELECT term, date_added
	FROM moz_input_history
	ORDER BY date_added DESC
	LIMIT 5000
`

// parseChromeHistory parses Chrome/Edge history SQLite database
func (d *Default) parseChromeHistory(dbPath string, profile string, errors *[]string) []models.BrowserHistory {
	var history []models.BrowserHistory

	if dbPath == "" {
		return history
	}

	// Create temp copy for reading
	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Chrome history DB: %v", err))
		}
		return history
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to open Chrome history DB: %v", err))
		}
		return history
	}
	defer db.Close()

	rows, err := db.Query(ChromeHistorySQL)
	if err != nil {
		return history
	}
	defer rows.Close()

	history = make([]models.BrowserHistory, 0)
	for rows.Next() {
		var h models.BrowserHistory
		var title, url sql.NullString
		var visitCount, visitDuration, fromVisit, isIndexed sql.NullInt64
		var visitTime, lastVisitTime sql.NullInt64
		var hidden sql.NullInt64

		err := rows.Scan(&url, &title, &visitCount, &visitDuration, &fromVisit, &isIndexed, &visitTime, &lastVisitTime, &hidden)
		if err != nil {
			continue
		}

		h.URL = url.String
		h.Title = title.String
		h.VisitCount = int(visitCount.Int64)
		h.Profile = profile
		h.FromDownload = fromVisit.Int64 > 0

		// Convert Chrome timestamp (microseconds since 1601-01-01) to time.Time
		if lastVisitTime.Valid && lastVisitTime.Int64 > 0 {
			h.VisitTime = chromeTimestampToTime(lastVisitTime.Int64)
		}

		history = append(history, h)
	}

	return history
}

// parseChromeDownloads parses Chrome/Edge downloads SQLite database
func (d *Default) parseChromeDownloads(dbPath string, profile string, errors *[]string) []models.BrowserDownload {
	var downloads []models.BrowserDownload

	if dbPath == "" {
		return downloads
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Chrome downloads DB: %v", err))
		}
		return downloads
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return downloads
	}
	defer db.Close()

	rows, err := db.Query(ChromeDownloadSQL)
	if err != nil {
		return downloads
	}
	defer rows.Close()

	downloads = make([]models.BrowserDownload, 0)
	for rows.Next() {
		var dl models.BrowserDownload
		var targetPath, url, mimeType, dangerType, lastModified sql.NullString
		var startTime, endTime, receivedBytes, totalBytes sql.NullInt64
		var opened, interruptReason sql.NullInt64

		err := rows.Scan(&targetPath, &url, &startTime, &endTime, &receivedBytes, &totalBytes, &mimeType, &dangerType, &opened, &interruptReason, &lastModified)
		if err != nil {
			continue
		}

		dl.TargetPath = targetPath.String
		dl.URL = url.String
		dl.FileSize = totalBytes.Int64
		dl.MimeType = mimeType.String
		dl.DangerType = dangerType.String
		dl.Opened = opened.Int64 == 1
		dl.Profile = profile

		if startTime.Valid && startTime.Int64 > 0 {
			dl.StartTime = chromeTimestampToTime(startTime.Int64)
		}
		if endTime.Valid && endTime.Int64 > 0 {
			dl.EndTime = chromeTimestampToTime(endTime.Int64)
		}

		downloads = append(downloads, dl)
	}

	return downloads
}

// parseChromeCookies parses Chrome/Edge cookies SQLite database
func (d *Default) parseChromeCookies(dbPath string, profile string, errors *[]string) []models.BrowserCookie {
	var cookies []models.BrowserCookie

	if dbPath == "" {
		return cookies
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Chrome cookies DB: %v", err))
		}
		return cookies
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return cookies
	}
	defer db.Close()

	rows, err := db.Query(ChromeCookieSQL)
	if err != nil {
		return cookies
	}
	defer rows.Close()

	cookies = make([]models.BrowserCookie, 0)
	for rows.Next() {
		var c models.BrowserCookie
		var hostKey, name, value, path, sameSite sql.NullString
		var creationUTC, expiresUTC, lastAccessUTC sql.NullInt64
		var isSecure, isHttpOnly, priority sql.NullInt64

		err := rows.Scan(&hostKey, &name, &value, &path, &creationUTC, &expiresUTC, &lastAccessUTC, &isSecure, &isHttpOnly, &sameSite, &priority)
		if err != nil {
			continue
		}

		c.Domain = hostKey.String
		c.Name = name.String
		c.Value = value.String
		c.Path = path.String
		c.HTTPOnly = isHttpOnly.Int64 == 1
		c.Secure = isSecure.Int64 == 1
		c.SameSite = sameSite.String
		c.Profile = profile

		if expiresUTC.Valid && expiresUTC.Int64 > 0 {
			c.Expires = chromeTimestampToTime(expiresUTC.Int64)
		}

		cookies = append(cookies, c)
	}

	return cookies
}

// parseChromeAutofill parses Chrome/Edge autofill SQLite database
func (d *Default) parseChromeAutofill(dbPath string, profile string, errors *[]string) []models.BrowserFormEntry {
	var entries []models.BrowserFormEntry

	if dbPath == "" {
		return entries
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Chrome autofill DB: %v", err))
		}
		return entries
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return entries
	}
	defer db.Close()

	rows, err := db.Query(ChromeAutofillSQL)
	if err != nil {
		return entries
	}
	defer rows.Close()

	entries = make([]models.BrowserFormEntry, 0)
	for rows.Next() {
		var e models.BrowserFormEntry
		var name, value sql.NullString
		var count, dateCreated, usageCount sql.NullInt64

		err := rows.Scan(&name, &value, &count, &dateCreated, &usageCount)
		if err != nil {
			continue
		}

		e.Name = name.String
		e.Value = value.String
		e.Count = int(count.Int64)
		e.Profile = profile

		entries = append(entries, e)
	}

	return entries
}

// parseFirefoxHistory parses Firefox history (places.sqlite)
func (d *Default) parseFirefoxHistory(dbPath string, profile string, errors *[]string) []models.BrowserHistory {
	var history []models.BrowserHistory

	if dbPath == "" {
		return history
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Firefox history DB: %v", err))
		}
		return history
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return history
	}
	defer db.Close()

	rows, err := db.Query(FirefoxHistorySQL)
	if err != nil {
		return history
	}
	defer rows.Close()

	history = make([]models.BrowserHistory, 0)
	for rows.Next() {
		var h models.BrowserHistory
		var url, title sql.NullString
		var visitDate, visitType, fromVisit sql.NullInt64

		err := rows.Scan(&url, &title, &visitDate, &visitType, &fromVisit)
		if err != nil {
			continue
		}

		h.URL = url.String
		h.Title = title.String
		h.Profile = profile

		if visitDate.Valid && visitDate.Int64 > 0 {
			h.VisitTime = firefoxTimestampToTime(visitDate.Int64)
		}

		history = append(history, h)
	}

	return history
}

// parseFirefoxCookies parses Firefox cookies
func (d *Default) parseFirefoxCookies(dbPath string, profile string, errors *[]string) []models.BrowserCookie {
	var cookies []models.BrowserCookie

	if dbPath == "" {
		return cookies
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Firefox cookies DB: %v", err))
		}
		return cookies
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return cookies
	}
	defer db.Close()

	rows, err := db.Query(FirefoxCookieSQL)
	if err != nil {
		return cookies
	}
	defer rows.Close()

	cookies = make([]models.BrowserCookie, 0)
	for rows.Next() {
		var c models.BrowserCookie
		var host, name, value, path, baseDomain sql.NullString
		var creationTime, expirationDate, lastAccessTime sql.NullFloat64
		var isSecure, isHttpOnly sql.NullInt64

		err := rows.Scan(&host, &name, &value, &path, &creationTime, &expirationDate, &lastAccessTime, &isSecure, &isHttpOnly, &baseDomain)
		if err != nil {
			continue
		}

		c.Domain = host.String
		c.Name = name.String
		c.Value = value.String
		c.Path = path.String
		c.HTTPOnly = isHttpOnly.Int64 == 1
		c.Secure = isSecure.Int64 == 1
		c.Profile = profile

		// Firefox timestamps are in microseconds since 1970
		if expirationDate.Valid && expirationDate.Float64 > 0 {
			c.Expires = time.Unix(int64(expirationDate.Float64), 0)
		}

		cookies = append(cookies, c)
	}

	return cookies
}

// parseFirefoxBookmarks parses Firefox bookmarks
func (d *Default) parseFirefoxBookmarks(dbPath string, profile string, errors *[]string) []models.BrowserBookmark {
	var bookmarks []models.BrowserBookmark

	if dbPath == "" {
		return bookmarks
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Firefox bookmarks DB: %v", err))
		}
		return bookmarks
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return bookmarks
	}
	defer db.Close()

	rows, err := db.Query(FirefoxBookmarksSQL)
	if err != nil {
		return bookmarks
	}
	defer rows.Close()

	bookmarks = make([]models.BrowserBookmark, 0)
	for rows.Next() {
		var b models.BrowserBookmark
		var title, url sql.NullString
		var dateAdded, lastModified sql.NullInt64
		var position, btype, visitCount sql.NullInt64

		err := rows.Scan(&title, &url, &dateAdded, &lastModified, &position, &btype, &visitCount)
		if err != nil {
			continue
		}

		b.Title = title.String
		b.URL = url.String
		b.Profile = profile

		if dateAdded.Valid && dateAdded.Int64 > 0 {
			b.AddDate = firefoxTimestampToTime(dateAdded.Int64)
		}

		bookmarks = append(bookmarks, b)
	}

	return bookmarks
}

// parseFirefoxSearch parses Firefox search history
func (d *Default) parseFirefoxSearch(dbPath string, profile string, errors *[]string) []models.BrowserSearch {
	var searches []models.BrowserSearch

	if dbPath == "" {
		return searches
	}

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to copy Firefox search DB: %v", err))
		}
		return searches
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return searches
	}
	defer db.Close()

	rows, err := db.Query(FirefoxSearchSQL)
	if err != nil {
		return searches
	}
	defer rows.Close()

	searches = make([]models.BrowserSearch, 0)
	for rows.Next() {
		var s models.BrowserSearch
		var term sql.NullString
		var dateAdded sql.NullInt64

		err := rows.Scan(&term, &dateAdded)
		if err != nil {
			continue
		}

		s.Query = term.String
		s.Profile = profile
		s.Engine = "Firefox"

		if dateAdded.Valid && dateAdded.Int64 > 0 {
			s.Time = firefoxTimestampToTime(dateAdded.Int64)
		}

		searches = append(searches, s)
	}

	return searches
}

// parseChromeBookmarksJSON parses Chrome bookmarks JSON file
func (d *Default) parseChromeBookmarksJSON(jsonPath string, profile string, errors *[]string) []models.BrowserBookmark {
	var bookmarks []models.BrowserBookmark

	if jsonPath == "" {
		return bookmarks
	}

	data, err := d.OSReadFile(jsonPath)
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to read Chrome bookmarks: %v", err))
		}
		return bookmarks
	}

	var root struct {
		Roots struct {
			BookmarkBar struct {
				Children []BookmarkNode `json:"children"`
			} `json:"bookmark_bar"`
			Other struct {
				Children []BookmarkNode `json:"children"`
			} `json:"other"`
			Synced struct {
				Children []BookmarkNode `json:"children"`
			} `json:"synced"`
		} `json:"roots"`
	}

	if err := json.Unmarshal(data, &root); err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to parse Chrome bookmarks JSON: %v", err))
		}
		return bookmarks
	}

	bookmarks = make([]models.BrowserBookmark, 0)
	d.extractBookmarkNodes(root.Roots.BookmarkBar.Children, "", &bookmarks, profile)
	d.extractBookmarkNodes(root.Roots.Other.Children, "Other", &bookmarks, profile)
	d.extractBookmarkNodes(root.Roots.Synced.Children, "Synced", &bookmarks, profile)

	return bookmarks
}

// BookmarkNode represents a Chrome bookmark node
type BookmarkNode struct {
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	URL          string          `json:"url,omitempty"`
	DateAdded    int64           `json:"date_added,omitempty"`
	DateModified int64           `json:"date_modified,omitempty"`
	Children     []BookmarkNode  `json:"children,omitempty"`
}

// extractBookmarkNodes recursively extracts bookmarks from JSON structure
func (d *Default) extractBookmarkNodes(nodes []BookmarkNode, folder string, bookmarks *[]models.BrowserBookmark, profile string) {
	for _, node := range nodes {
		if node.Type == "url" && node.URL != "" {
			*bookmarks = append(*bookmarks, models.BrowserBookmark{
				Title:   node.Name,
				URL:     node.URL,
				Folder:  folder,
				Profile: profile,
				AddDate: time.UnixMicro(node.DateAdded),
			})
		} else if node.Type == "folder" && len(node.Children) > 0 {
			newFolder := folder
			if newFolder != "" {
				newFolder += "/"
			}
			newFolder += node.Name
			d.extractBookmarkNodes(node.Children, newFolder, bookmarks, profile)
		}
	}
}

// parseChromeExtensionsJSON parses Chrome extensions from JSON
func (d *Default) parseChromeExtensionsJSON(jsonPath string, profile string, errors *[]string) []models.BrowserExtension {
	var extensions []models.BrowserExtension

	if jsonPath == "" {
		return extensions
	}

	data, err := d.OSReadFile(jsonPath)
	if err != nil {
		return extensions
	}

	var root struct {
		Extensions []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
			Enabled     bool   `json:"enabled"`
		} `json:"extensions"`
	}

	if err := json.Unmarshal(data, &root); err != nil {
		return extensions
	}

	extensions = make([]models.BrowserExtension, 0)
	for _, ext := range root.Extensions {
		extensions = append(extensions, models.BrowserExtension{
			ID:          ext.ID,
			Name:        ext.Name,
			Version:     ext.Version,
			Description: ext.Description,
			Enabled:     ext.Enabled,
			Profile:     profile,
		})
	}

	return extensions
}

// chromeTimestampToTime converts Chrome timestamp (microseconds since 1601-01-01) to time.Time
func chromeTimestampToTime(chromeTime int64) time.Time {
	// Chrome uses microseconds since 1601-01-01 UTC
	epoch := time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC)
	return epoch.Add(time.Duration(chromeTime) * time.Microsecond)
}

// firefoxTimestampToTime converts Firefox timestamp (microseconds since 1970) to time.Time
func firefoxTimestampToTime(firefoxTime int64) time.Time {
	// Firefox uses microseconds since 1970-01-01 UTC
	return time.UnixMicro(firefoxTime)
}

// copyDBForReading creates a temporary copy of a database file for reading
func (d *Default) copyDBForReading(dbPath string) (string, error) {
	if dbPath == "" {
		return "", fmt.Errorf("empty db path")
	}

	// Check if file exists
	if _, err := d.OSStat(dbPath); err != nil {
		return "", err
	}

	// Create temp file
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("tracium_%d.db", time.Now().UnixNano()))

	// Copy the file
	source, err := d.OSOpen(dbPath)
	if err != nil {
		return "", err
	}
	defer source.Close()

	dest, err := d.OSCreate(tmpFile)
	if err != nil {
		return "", err
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	if err != nil {
		return "", err
	}

	return tmpFile, nil
}

// cleanupTempFile removes a temporary file
func (d *Default) cleanupTempFile(path string) {
	if path != "" {
		os.Remove(path)
	}
}

// CollectBrowserArtifacts collects structured browser artifacts
func (d *Default) CollectBrowserArtifacts(errors *[]string) models.BrowserArtifacts {
	browser := models.BrowserArtifacts{
		Profiles:    make([]models.BrowserProfile, 0),
		History:     make([]models.BrowserHistory, 0),
		Downloads:   make([]models.BrowserDownload, 0),
		Uploads:     make([]models.BrowserUpload, 0),
		Cookies:     make([]models.BrowserCookie, 0),
		FormEntries: make([]models.BrowserFormEntry, 0),
		Searches:    make([]models.BrowserSearch, 0),
		Bookmarks:   make([]models.BrowserBookmark, 0),
		Extensions:  make([]models.BrowserExtension, 0),
	}

	// Get home directories
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to get home directories: %v", err))
		}
		return browser
	}

	osName := d.OSName()

	for _, homeDir := range homeDirs {
		// Chrome
		chromeBase := d.getBrowserBasePath(homeDir, osName, "chrome")
		if chromeBase != "" {
			d.collectChromiumBrowserArtifacts(chromeBase, "chrome", &browser, errors)
		}

		// Edge
		edgeBase := d.getBrowserBasePath(homeDir, osName, "edge")
		if edgeBase != "" {
			d.collectChromiumBrowserArtifacts(edgeBase, "edge", &browser, errors)
		}

		// Firefox
		firefoxBase := d.getBrowserBasePath(homeDir, osName, "firefox")
		if firefoxBase != "" {
			d.collectFirefoxArtifacts(firefoxBase, "firefox", &browser, errors)
		}

		// Opera
		operaBase := d.getBrowserBasePath(homeDir, osName, "opera")
		if operaBase != "" {
			d.collectChromiumBrowserArtifacts(operaBase, "opera", &browser, errors)
		}

		// Brave
		braveBase := d.getBrowserBasePath(homeDir, osName, "brave")
		if braveBase != "" {
			d.collectChromiumBrowserArtifacts(braveBase, "brave", &browser, errors)
		}
	}

	return browser
}

// getBrowserBasePath returns the base path for a browser based on OS
func (d *Default) getBrowserBasePath(homeDir, osName, browser string) string {
	switch osName {
	case "windows":
		switch browser {
		case "chrome":
			return filepath.Join(homeDir, "AppData", "Local", "Google", "Chrome", "User Data")
		case "edge":
			return filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Edge", "User Data")
		case "firefox":
			return filepath.Join(homeDir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
		case "opera":
			return filepath.Join(homeDir, "AppData", "Roaming", "Opera Software", "Opera Stable")
		case "brave":
			return filepath.Join(homeDir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")
		}
	case "darwin":
		switch browser {
		case "chrome":
			return filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome")
		case "edge":
			return filepath.Join(homeDir, "Library", "Application Support", "Microsoft Edge")
		case "firefox":
			return filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles")
		case "opera":
			return filepath.Join(homeDir, "Library", "Application Support", "com.operasoftware.Opera")
		case "brave":
			return filepath.Join(homeDir, "Library", "Application Support", "BraveSoftware", "Brave-Browser")
		}
	case "linux":
		switch browser {
		case "chrome":
			return filepath.Join(homeDir, ".config", "google-chrome")
		case "edge":
			return filepath.Join(homeDir, ".config", "microsoft-edge")
		case "firefox":
			return filepath.Join(homeDir, ".mozilla", "firefox")
		case "opera":
			return filepath.Join(homeDir, ".config", "opera")
		case "brave":
			return filepath.Join(homeDir, ".config", "BraveSoftware", "Brave-Browser")
		}
	}
	return ""
}

// collectChromiumBrowserArtifacts collects artifacts from Chromium-based browsers
func (d *Default) collectChromiumBrowserArtifacts(basePath, browserName string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := d.OSStat(basePath); err != nil {
		return
	}

	// Find all profile directories
	profileDirs := d.findChromiumProfiles(basePath)
	if len(profileDirs) == 0 {
		// Try Default profile
		defaultProfile := filepath.Join(basePath, "Default")
		if _, err := d.OSStat(defaultProfile); err == nil {
			profileDirs = []string{defaultProfile}
		}
	}

	for i, profileDir := range profileDirs {
		profileName := filepath.Base(profileDir)
		if profileName == basePath {
			profileName = "Default"
		}

		isDefault := i == 0

		// Add profile
		browser.Profiles = append(browser.Profiles, models.BrowserProfile{
			ID:        profileName,
			Name:      profileName,
			Path:      profileDir,
			Browser:   browserName,
			IsDefault: isDefault,
		})

		// History
		historyPath := filepath.Join(profileDir, "History")
		if _, err := d.OSStat(historyPath); err == nil {
			history := d.parseChromeHistory(historyPath, profileName, errors)
			browser.History = append(browser.History, history...)

			// Parse uploads from history (is_upload_page = true)
			uploads := d.detectUploadsFromHistory(historyPath, profileName, errors)
			browser.Uploads = append(browser.Uploads, uploads...)
		}

		// Cookies
		cookiesPath := filepath.Join(profileDir, "Cookies")
		if _, err := d.OSStat(cookiesPath); err == nil {
			cookies := d.parseChromeCookies(cookiesPath, profileName, errors)
			browser.Cookies = append(browser.Cookies, cookies...)
		}

		// Downloads
		downloadsPath := filepath.Join(profileDir, "History")
		if _, err := d.OSStat(downloadsPath); err == nil {
			downloads := d.parseChromeDownloads(downloadsPath, profileName, errors)
			browser.Downloads = append(browser.Downloads, downloads...)
		}

		// Web Data (autofill)
		webDataPath := filepath.Join(profileDir, "Web Data")
		if _, err := d.OSStat(webDataPath); err == nil {
			autofill := d.parseChromeAutofill(webDataPath, profileName, errors)
			browser.FormEntries = append(browser.FormEntries, autofill...)
		}

		// Bookmarks (JSON)
		bookmarksPath := filepath.Join(profileDir, "Bookmarks")
		if _, err := d.OSStat(bookmarksPath); err == nil {
			bookmarks := d.parseChromeBookmarksJSON(bookmarksPath, profileName, errors)
			browser.Bookmarks = append(browser.Bookmarks, bookmarks...)
		}

		// Extensions (from Preferences)
		extensionsPath := filepath.Join(profileDir, "Default", "Extensions")
		if _, err := d.OSStat(extensionsPath); err == nil {
			// Parse extensions.json if exists
			extJSON := filepath.Join(profileDir, "Default", "Local Extension Settings")
			if _, err := d.OSStat(extJSON); err == nil {
				// Extensions are stored in individual folders
				extensions := d.collectChromiumExtensions(extensionsPath, profileName)
				browser.Extensions = append(browser.Extensions, extensions...)
			}
		}
	}
}

// findChromiumProfiles finds all Chromium profile directories
func (d *Default) findChromiumProfiles(basePath string) []string {
	var profiles []string

	entries, err := d.OSReadDir(basePath)
	if err != nil {
		return profiles
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Match Default, Profile *, System Profile
		if name == "Default" || strings.HasPrefix(name, "Profile") || strings.HasPrefix(name, "System Profile") {
			profiles = append(profiles, filepath.Join(basePath, name))
		}
	}

	return profiles
}

// collectChromiumExtensions collects extension information from directories
func (d *Default) collectChromiumExtensions(extensionsDir string, profile string) []models.BrowserExtension {
	var extensions []models.BrowserExtension

	entries, err := d.OSReadDir(extensionsDir)
	if err != nil {
		return extensions
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		extID := entry.Name()

		// Try to read manifest.json for extension info
		manifestPath := filepath.Join(extensionsDir, extID, "manifest.json")
		data, err := d.OSReadFile(manifestPath)
		if err != nil {
			continue
		}

		var manifest struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
		}

		if json.Unmarshal(data, &manifest) == nil {
			extensions = append(extensions, models.BrowserExtension{
				ID:          extID,
				Name:        manifest.Name,
				Version:     manifest.Version,
				Description: manifest.Description,
				Enabled:     true,
				Profile:     profile,
			})
		}
	}

	return extensions
}

// detectUploadsFromHistory detects file uploads from browser history
func (d *Default) detectUploadsFromHistory(historyPath, profile string, errors *[]string) []models.BrowserUpload {
	var uploads []models.BrowserUpload

	tmpFile, err := d.copyDBForReading(historyPath)
	if err != nil {
		return uploads
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return uploads
	}
	defer db.Close()

	// Cloud upload destinations
	uploadDomains := []string{
		"drive.google.com",
		"dropbox.com",
		"onedrive.live.com",
		"wetrasnfer.com",
		"icloud.com",
		"box.com",
		"docs.google.com",
	}

	query := `
		SELECT url, title, visit_count, last_visit_time
		FROM urls
		WHERE url LIKE '%upload%' OR url LIKE '%file%' OR url LIKE '%cloud%'
		ORDER BY last_visit_time DESC
		LIMIT 1000
	`

	rows, err := db.Query(query)
	if err != nil {
		return uploads
	}
	defer rows.Close()

	uploads = make([]models.BrowserUpload, 0)
	for rows.Next() {
		var u models.BrowserUpload
		var url, title sql.NullString
		var visitCount sql.NullInt64
		var lastVisitTime sql.NullInt64

		err := rows.Scan(&url, &title, &visitCount, &lastVisitTime)
		if err != nil {
			continue
		}

		urlStr := url.String

		// Check if it's a known upload service
		isUpload := false
		for _, domain := range uploadDomains {
			if strings.Contains(urlStr, domain) && (strings.Contains(urlStr, "upload") || strings.Contains(urlStr, "file") || strings.Contains(urlStr, "share")) {
				isUpload = true
				break
			}
		}

		if isUpload {
			u.DestinationURL = urlStr
			u.Profile = profile
			if title.Valid {
				u.SourcePath = title.String
			}
			if lastVisitTime.Valid && lastVisitTime.Int64 > 0 {
				u.UploadTime = chromeTimestampToTime(lastVisitTime.Int64)
			}
			uploads = append(uploads, u)
		}
	}

	return uploads
}

// collectFirefoxArtifacts collects Firefox browser artifacts
func (d *Default) collectFirefoxArtifacts(profilesPath, browserName string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := d.OSStat(profilesPath); err != nil {
		return
	}

	// Find Firefox profile directories
	pattern := filepath.Join(profilesPath, "*.default*")
	profileDirs, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	for i, profileDir := range profileDirs {
		profileName := filepath.Base(profileDir)
		isDefault := i == 0

		// Add profile
		browser.Profiles = append(browser.Profiles, models.BrowserProfile{
			ID:        profileName,
			Name:      profileName,
			Path:      profileDir,
			Browser:   browserName,
			IsDefault: isDefault,
		})

		// History (places.sqlite)
		placesPath := filepath.Join(profileDir, "places.sqlite")
		if _, err := d.OSStat(placesPath); err == nil {
			history := d.parseFirefoxHistory(placesPath, profileName, errors)
			browser.History = append(browser.History, history...)
		}

		// Cookies
		cookiesPath := filepath.Join(profileDir, "cookies.sqlite")
		if _, err := d.OSStat(cookiesPath); err == nil {
			cookies := d.parseFirefoxCookies(cookiesPath, profileName, errors)
			browser.Cookies = append(browser.Cookies, cookies...)
		}

		// Bookmarks
		bookmarksPath := filepath.Join(profileDir, "places.sqlite")
		if _, err := d.OSStat(bookmarksPath); err == nil {
			bookmarks := d.parseFirefoxBookmarks(bookmarksPath, profileName, errors)
			browser.Bookmarks = append(browser.Bookmarks, bookmarks...)
		}

		// Search history
		searchPath := filepath.Join(profileDir, "places.sqlite")
		if _, err := d.OSStat(searchPath); err == nil {
			searches := d.parseFirefoxSearch(searchPath, profileName, errors)
			browser.Searches = append(browser.Searches, searches...)
		}

		// Form history
		formHistoryPath := filepath.Join(profileDir, "formhistory.sqlite")
		if _, err := d.OSStat(formHistoryPath); err == nil {
			formEntries := d.parseFirefoxFormHistory(formHistoryPath, profileName, errors)
			browser.FormEntries = append(browser.FormEntries, formEntries...)
		}

		// Extensions
		extensionsPath := filepath.Join(profileDir, "extensions.json")
		if _, err := d.OSStat(extensionsPath); err == nil {
			extensions := d.parseFirefoxExtensionsJSON(extensionsPath, profileName, errors)
			browser.Extensions = append(browser.Extensions, extensions...)
		}
	}
}

// parseFirefoxFormHistory parses Firefox form history
func (d *Default) parseFirefoxFormHistory(dbPath, profile string, errors *[]string) []models.BrowserFormEntry {
	var entries []models.BrowserFormEntry

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		return entries
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return entries
	}
	defer db.Close()

	query := `SELECT fieldname, value, timesused, lastused FROM moz_formhistory ORDER BY lastused DESC LIMIT 5000`

	rows, err := db.Query(query)
	if err != nil {
		return entries
	}
	defer rows.Close()

	entries = make([]models.BrowserFormEntry, 0)
	for rows.Next() {
		var e models.BrowserFormEntry
		var fieldname, value sql.NullString
		var timesused, lastused sql.NullInt64

		err := rows.Scan(&fieldname, &value, &timesused, &lastused)
		if err != nil {
			continue
		}

		e.Name = fieldname.String
		e.Value = value.String
		e.Count = int(timesused.Int64)
		e.Profile = profile

		entries = append(entries, e)
	}

	return entries
}

// parseFirefoxExtensionsJSON parses Firefox extensions JSON
func (d *Default) parseFirefoxExtensionsJSON(jsonPath, profile string, errors *[]string) []models.BrowserExtension {
	var extensions []models.BrowserExtension

	data, err := d.OSReadFile(jsonPath)
	if err != nil {
		return extensions
	}

	var root struct {
		Addons []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
			Active      bool   `json:"active"`
		} `json:"addons"`
	}

	if err := json.Unmarshal(data, &root); err != nil {
		return extensions
	}

	extensions = make([]models.BrowserExtension, 0)
	for _, ext := range root.Addons {
		extensions = append(extensions, models.BrowserExtension{
			ID:          ext.ID,
			Name:        ext.Name,
			Version:     ext.Version,
			Description: ext.Description,
			Enabled:     ext.Active,
			Profile:     profile,
		})
	}

	return extensions
}

// CollectCommunicationArtifacts collects structured communication artifacts
func (d *Default) CollectCommunicationArtifacts(errors *[]string) models.CommunicationArtifacts {
	comm := models.CommunicationArtifacts{
		Emails:      make([]models.EmailArtifact, 0),
		Messages:    make([]models.MessageArtifact, 0),
		Attachments: make([]models.AttachmentArtifact, 0),
		Contacts:    make([]models.ContactArtifact, 0),
		CallLogs:    make([]models.CallLogArtifact, 0),
	}

	// Get home directories
	homeDirs, err := d.OSUserHomeDirs()
	if err != nil {
		if errors != nil {
			*errors = append(*errors, fmt.Sprintf("failed to get home directories: %v", err))
		}
		return comm
	}

	osName := d.OSName()

	for _, homeDir := range homeDirs {
		// Outlook
		d.collectOutlookArtifacts(homeDir, osName, &comm, errors)

		// Thunderbird
		d.collectThunderbirdCommunicationArtifacts(homeDir, osName, &comm, errors)

		// WhatsApp Desktop
		d.collectWhatsAppArtifacts(homeDir, osName, &comm, errors)

		// Telegram Desktop
		d.collectTelegramArtifacts(homeDir, osName, &comm, errors)

		// Slack
		d.collectSlackArtifacts(homeDir, osName, &comm, errors)

		// Microsoft Teams
		d.collectTeamsArtifacts(homeDir, osName, &comm, errors)

		// Windows Mail
		d.collectWindowsMailArtifacts(homeDir, osName, &comm, errors)
	}

	return comm
}

// collectOutlookArtifacts collects Outlook PST/OST artifacts
func (d *Default) collectOutlookArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	var searchPaths []string

	switch osName {
	case "windows":
		searchPaths = []string{
			filepath.Join(homeDir, "Documents", "Outlook Files"),
			filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Outlook"),
			filepath.Join(homeDir, "AppData", "Roaming", "Microsoft", "Outlook"),
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(homeDir, "Documents", "Outlook Files"),
			filepath.Join(homeDir, "Library", "Group Containers", "UBF8T346G9.Office", "Outlook"),
		}
	}

	for _, searchPath := range searchPaths {
		if _, err := d.OSStat(searchPath); err != nil {
			continue
		}

		entries, err := d.OSReadDir(searchPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			nameLower := strings.ToLower(entry.Name())
			if strings.HasSuffix(nameLower, ".pst") || strings.HasSuffix(nameLower, ".ost") {
				// Add as email artifact (PST/OST parsing would require additional library)
				email := models.EmailArtifact{
					ID:        entry.Name(),
					Subject:   nameLower,
					Folder:    "outlook",
					HasAttachment: false,
				}
				comm.Emails = append(comm.Emails, email)
			}
		}
	}
}

// collectThunderbirdCommunicationArtifacts collects Thunderbird artifacts
func (d *Default) collectThunderbirdCommunicationArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	var searchPaths []string

	switch osName {
	case "windows":
		searchPaths = []string{filepath.Join(homeDir, "AppData", "Roaming", "Thunderbird", "Profiles")}
	case "darwin":
		searchPaths = []string{filepath.Join(homeDir, "Library", "Application Support", "Thunderbird", "Profiles")}
	case "linux":
		searchPaths = []string{filepath.Join(homeDir, ".thunderbird")}
	}

	for _, searchPath := range searchPaths {
		if _, err := d.OSStat(searchPath); err != nil {
			continue
		}

		// Find profile directories
		pattern := filepath.Join(searchPath, "*.default*")
		profileDirs, _ := filepath.Glob(pattern)

		for _, profileDir := range profileDirs {
			// Look for mail directories
			mailDir := filepath.Join(profileDir, "Mail")
			if _, err := d.OSStat(mailDir); err != nil {
				continue
			}

			entries, err := d.OSReadDir(mailDir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}

				mailboxPath := filepath.Join(mailDir, entry.Name())
				d.parseThunderbirdMailbox(mailboxPath, comm, errors)
			}
		}
	}
}

// parseThunderbirdMailbox parses Thunderbird mailbox
func (d *Default) parseThunderbirdMailbox(mailboxPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := d.OSStat(mailboxPath); err != nil {
		return
	}

	entries, err := d.OSReadDir(mailboxPath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		nameLower := strings.ToLower(entry.Name())

		// Determine folder
		folder := "inbox"
		if strings.Contains(nameLower, "sent") {
			folder = "sent"
		} else if strings.Contains(nameLower, "draft") {
			folder = "drafts"
		} else if strings.Contains(nameLower, "trash") || strings.Contains(nameLower, "deleted") {
			folder = "trash"
		}

		// Try to parse as mbox
		mboxPath := filepath.Join(mailboxPath, entry.Name())
		if strings.HasSuffix(nameLower, ".msf") {
			continue // Skip index files
		}

		// Add email artifact
		email := models.EmailArtifact{
			ID:              mboxPath,
			Subject:         entry.Name(),
			Folder:          folder,
			HasAttachment:   false,
		}
		comm.Emails = append(comm.Emails, email)
	}
}

// collectWhatsAppArtifacts collects WhatsApp Desktop artifacts
func (d *Default) collectWhatsAppArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	var searchPaths []string

	switch osName {
	case "windows":
		searchPaths = []string{
			filepath.Join(homeDir, "AppData", "Local", "WhatsApp"),
			filepath.Join(homeDir, "AppData", "Roaming", "WhatsApp"),
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "WhatsApp"),
			filepath.Join(homeDir, "Library", "Containers", "net.whatsapp.WhatsApp"),
		}
	}

	for _, searchPath := range searchPaths {
		if _, err := d.OSStat(searchPath); err != nil {
			continue
		}

		// Look for message database
		msgstorePaths := []string{
			filepath.Join(searchPath, "msgstore.db"),
			filepath.Join(searchPath, "msgstore.db.crypt14"),
			filepath.Join(searchPath, "msgstore.db.crypt15"),
			filepath.Join(searchPath, "msgstore.db.crypt16"),
		}

		for _, msgstorePath := range msgstorePaths {
			if _, err := d.OSStat(msgstorePath); err == nil {
				messages := d.parseWhatsAppMessages(msgstorePath, errors)
				comm.Messages = append(comm.Messages, messages...)

				// Add contact from WhatsApp
				comm.Contacts = append(comm.Contacts, models.ContactArtifact{
					App: "whatsapp",
				})
				break
			}
		}

		// Look for media directory
		mediaPath := filepath.Join(searchPath, "Media")
		if _, err := d.OSStat(mediaPath); err == nil {
			d.collectWhatsAppMedia(mediaPath, comm, errors)
		}
	}
}

// parseWhatsAppMessages parses WhatsApp message database
func (d *Default) parseWhatsAppMessages(dbPath string, errors *[]string) []models.MessageArtifact {
	var messages []models.MessageArtifact

	tmpFile, err := d.copyDBForReading(dbPath)
	if err != nil {
		return messages
	}
	defer d.cleanupTempFile(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		return messages
	}
	defer db.Close()

	query := `
		SELECT _id, key_remote_jid, key_from_me, body, timestamp, media_wa_type, media_caption, deleted
		FROM messages
		ORDER BY timestamp DESC
		LIMIT 5000
	`

	rows, err := db.Query(query)
	if err != nil {
		return messages
	}
	defer rows.Close()

	messages = make([]models.MessageArtifact, 0)
	for rows.Next() {
		var m models.MessageArtifact
		var id, remoteJID, body sql.NullString
		var fromMe, timestamp, mediaType sql.NullInt64
		var mediaCaption, deleted sql.NullInt64

		err := rows.Scan(&id, &remoteJID, &fromMe, &body, &timestamp, &mediaType, &mediaCaption, &deleted)
		if err != nil {
			continue
		}

		m.App = "whatsapp"
		m.Receiver = remoteJID.String
		m.Content = body.String
		m.Deleted = deleted.Int64 == 1

		if fromMe.Int64 == 1 {
			m.Sender = "me"
		}

		if timestamp.Valid && timestamp.Int64 > 0 {
			m.Timestamp = time.Unix(timestamp.Int64, 0)
		}

		if mediaType.Valid && mediaType.Int64 > 0 {
			m.HasFile = true
		}

		messages = append(messages, m)
	}

	return messages
}

// collectWhatsAppMedia collects WhatsApp media files
func (d *Default) collectWhatsAppMedia(mediaPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := d.OSStat(mediaPath); err != nil {
		return
	}

	entries, err := d.OSReadDir(mediaPath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		att := models.AttachmentArtifact{
			ID:        entry.Name(),
			FilePath:  filepath.Join(mediaPath, entry.Name()),
			SourceApp: "whatsapp",
		}
		comm.Attachments = append(comm.Attachments, att)
	}
}

// collectTelegramArtifacts collects Telegram Desktop artifacts
func (d *Default) collectTelegramArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	var searchPaths []string

	switch osName {
	case "windows":
		searchPaths = []string{filepath.Join(homeDir, "AppData", "Roaming", "Telegram Desktop")}
	case "darwin":
		searchPaths = []string{filepath.Join(homeDir, "Library", "Application Support", "Telegram Desktop")}
	case "linux":
		searchPaths = []string{filepath.Join(homeDir, ".local", "share", "TelegramDesktop")}
	}

	for _, searchPath := range searchPaths {
		if _, err := d.OSStat(searchPath); err != nil {
			continue
		}

		// Look for tdata directory
		tdataPath := filepath.Join(searchPath, "tdata")
		if _, err := d.OSStat(tdataPath); err == nil {
			// Telegram uses encrypted databases - collect as attachments
			entries, _ := d.OSReadDir(tdataPath)
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				att := models.AttachmentArtifact{
					ID:        entry.Name(),
					FilePath:  filepath.Join(tdataPath, entry.Name()),
					SourceApp: "telegram",
				}
				comm.Attachments = append(comm.Attachments, att)
			}
		}

		// Look for message database
		msgDBPaths := []string{
			filepath.Join(searchPath, "messages.db"),
			filepath.Join(searchPath, "tdata", "accounts"),
		}

		for _, msgDBPath := range msgDBPaths {
			if _, err := d.OSStat(msgDBPath); err == nil {
				messages := d.parseTelegramMessages(msgDBPath, errors)
				comm.Messages = append(comm.Messages, messages...)
			}
		}
	}
}

// parseTelegramMessages parses Telegram message database
func (d *Default) parseTelegramMessages(dbPath string, errors *[]string) []models.MessageArtifact {
	var messages []models.MessageArtifact

	// Telegram databases are typically encrypted
	// We'll add a placeholder for now
	messages = append(messages, models.MessageArtifact{
		App:       "telegram",
		Content:   "Telegram messages stored in encrypted database",
		Timestamp: time.Now(),
	})

	return messages
}

// collectSlackArtifacts collects Slack artifacts
func (d *Default) collectSlackArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	var searchPaths []string

	switch osName {
	case "windows":
		searchPaths = []string{filepath.Join(homeDir, "AppData", "Roaming", "Slack")}
	case "darwin":
		searchPaths = []string{filepath.Join(homeDir, "Library", "Application Support", "Slack")}
	case "linux":
		searchPaths = []string{filepath.Join(homeDir, ".config", "Slack")}
	}

	for _, searchPath := range searchPaths {
		if _, err := d.OSStat(searchPath); err != nil {
			continue
		}

		// Look for Slack cache and storage
		storagePath := filepath.Join(searchPath, "storage")
		if _, err := d.OSStat(storagePath); err == nil {
			entries, _ := d.OSReadDir(storagePath)
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				// Slack stores messages in JSON files
				data, err := d.OSReadFile(filepath.Join(storagePath, entry.Name()))
				if err == nil {
					d.parseSlackMessages(data, comm, errors)
				}
			}
		}
	}
}

// parseSlackMessages parses Slack message storage
func (d *Default) parseSlackMessages(data []byte, comm *models.CommunicationArtifacts, errors *[]string) {
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return
	}

	// Try to extract messages from Slack storage format
	if items, ok := root["items"].([]interface{}); ok {
		for _, item := range items {
			if msgMap, ok := item.(map[string]interface{}); ok {
				var msg models.MessageArtifact
				msg.App = "slack"

				if v, ok := msgMap["text"].(string); ok {
					msg.Content = v
				}
				if v, ok := msgMap["user"].(string); ok {
					msg.Sender = v
				}
				if v, ok := msgMap["ts"].(float64); ok {
					msg.Timestamp = time.Unix(int64(v), 0)
				}

				comm.Messages = append(comm.Messages, msg)
			}
		}
	}
}

// collectTeamsArtifacts collects Microsoft Teams artifacts
func (d *Default) collectTeamsArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	var searchPaths []string

	switch osName {
	case "windows":
		searchPaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Microsoft", "Teams"),
			filepath.Join(homeDir, "AppData", "Local", "Packages", "MSTeams*"),
		}
	case "darwin":
		searchPaths = []string{filepath.Join(homeDir, "Library", "Application Support", "Teams")}
	case "linux":
		searchPaths = []string{filepath.Join(homeDir, ".config", "Microsoft Teams")}
	}

	for _, searchPath := range searchPaths {
		// Handle glob patterns
		matches, _ := filepath.Glob(searchPath)
		for _, path := range matches {
			if _, err := d.OSStat(path); err != nil {
				continue
			}

			// Look for IndexedDB
			indexedDBPath := filepath.Join(path, "IndexedDB")
			if _, err := d.OSStat(indexedDBPath); err == nil {
				// Teams stores messages in LevelDB/IndexedDB
				// Add as generic Teams message
				comm.Messages = append(comm.Messages, models.MessageArtifact{
					App:       "teams",
					Content:   "Teams messages stored in IndexedDB",
					Timestamp: time.Now(),
				})
			}

			// Look for cache
			cachePath := filepath.Join(path, "Cache")
			if _, err := d.OSStat(cachePath); err == nil {
				entries, _ := d.OSReadDir(cachePath)
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					att := models.AttachmentArtifact{
						ID:        entry.Name(),
						FilePath:  filepath.Join(cachePath, entry.Name()),
						SourceApp: "teams",
					}
					comm.Attachments = append(comm.Attachments, att)
				}
			}
		}
	}
}

// collectWindowsMailArtifacts collects Windows Mail artifacts
func (d *Default) collectWindowsMailArtifacts(homeDir, osName string, comm *models.CommunicationArtifacts, errors *[]string) {
	if osName != "windows" {
		return
	}

	searchPaths := []string{
		filepath.Join(homeDir, "AppData", "Local", "Comms", "Unistore", "data"),
		filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Windows Mail"),
	}

	for _, searchPath := range searchPaths {
		if _, err := d.OSStat(searchPath); err != nil {
			continue
		}

		// Windows Mail uses local database
		entries, _ := d.OSReadDir(searchPath)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			email := models.EmailArtifact{
				ID:            entry.Name(),
				Folder:        "windows-mail",
				HasAttachment: false,
			}
			comm.Emails = append(comm.Emails, email)
		}
	}
}
