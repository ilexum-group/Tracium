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
	"path"
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

// CollectBrowserArtifacts collects browser artifacts (dummy implementation)
func (d *Default) CollectBrowserArtifacts(_ *[]string) models.BrowserArtifacts {
	return models.BrowserArtifacts{}
}

// CollectCommunicationArtifacts collects communication artifacts (dummy implementation)
func (d *Default) CollectCommunicationArtifacts(_ *[]string) models.CommunicationArtifacts {
	return models.CommunicationArtifacts{}
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

// CopyFileArtifact copies a file if it exists, parses it, and returns its metadata
func (d *Default) CopyFileArtifact(src, prefix, browser string) (*models.ForensicFile, error) {
	if _, err := d.OSStat(src); err != nil {
		return nil, fmt.Errorf("artifact missing: %s", src)
	}

	// Read file content for parsing
	//nolint:gosec // G304: src is from trusted forensics collection sources
	sourceFile, err := d.OSOpen(src)
	if err != nil {
		return nil, fmt.Errorf("open failed for %s: %w", src, err)
	}

	data, err := io.ReadAll(sourceFile)
	_ = sourceFile.Close()
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %w", src, err)
	}

	// Detect file type and parse content
	parser := NewArtifactParser()
	filename := filepath.Base(src)
	parseResult := parser.DetectAndParse(data, filename)

	// Determine file type for category
	fileType := GetFileType(data, filename)
	category := "browser_db"
	if strings.Contains(fileType, "SQLite") {
		category = "browser_sqlite"
	} else if strings.Contains(fileType, "JSON") {
		category = "browser_json"
	} else if strings.Contains(fileType, "Text") {
		category = "browser_text"
	}

	// Write to temp only if needed (for large files)
	needsCopy := len(data) > 10*1024*1024 // Only copy if > 10MB
	var dest string
	var written int64

	if needsCopy {
		dest = filepath.Join(os.TempDir(), fmt.Sprintf("%s_%d.db", prefix, time.Now().UnixNano()))
		//nolint:gosec // G304: dest is controlled output path
		destFile, err := d.OSCreate(dest)
		if err != nil {
			return nil, fmt.Errorf("copy failed for %s: %w", src, err)
		}
		writtenInt, err := destFile.Write(data)
		_ = destFile.Close()
		if err != nil {
			return nil, fmt.Errorf("write failed for %s: %w", src, err)
		}
		written = int64(writtenInt)
	} else {
		written = int64(len(data))
	}

	// Compute hash
	hasher := sha256.New()
	hasher.Write(data)
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	return &models.ForensicFile{
		Name:         filename,
		Path:         dest,
		SourcePath:   src,
		Size:         written,
		Hash:         hash,
		Category:     category,
		Browser:      browser,
		Data:         parseResult.Content, // Parsed content (JSON/text) or base64
		DataFormat:   parseResult.Format,   // "json", "text", "base64"
		FileType:     fileType,             // Human readable file type
		TableCount:   parseResult.TableCount, // Number of tables if SQLite
		ParseError:   parseResult.Error,     // Error message if parsing failed
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

// collectChromeProfileArtifacts collects Chrome/Chromium profile artifacts (shared by Linux and Darwin)
func (d *Default) collectChromeProfileArtifacts(profileDir string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := d.OSStat(profileDir); err != nil {
		return
	}

	// History
	historyFiles := []string{"History", "History.db"}
	for _, name := range historyFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := d.CopyFileArtifact(src, "chrome_history", "chrome"); err == nil {
			artifact.Category = "history"
			browser.History = append(browser.History, *artifact)
		} else if errors != nil && !strings.Contains(err.Error(), "artifact missing") {
			*errors = append(*errors, err.Error())
		}
	}

	// Cookies
	cookieFiles := []string{"Cookies", "Cookies.db"}
	for _, name := range cookieFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := d.CopyFileArtifact(src, "chrome_cookies", "chrome"); err == nil {
			artifact.Category = "cookies"
			browser.Cookies = append(browser.Cookies, *artifact)
		} else if errors != nil && !strings.Contains(err.Error(), "artifact missing") {
			*errors = append(*errors, err.Error())
		}
	}

	// Downloads
	downloadFiles := []string{"DownloadMetadata"}
	for _, name := range downloadFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := d.CopyFileArtifact(src, "chrome_downloads", "chrome"); err == nil {
			artifact.Category = "downloads"
			browser.Downloads = append(browser.Downloads, *artifact)
		}
	}

	// Bookmarks
	src := filepath.Join(profileDir, "Bookmarks")
	if artifact, err := d.CopyFileArtifact(src, "chrome_bookmarks", "chrome"); err == nil {
		artifact.Category = "bookmarks"
		browser.Bookmarks = append(browser.Bookmarks, *artifact)
	}

	// Login/Autofill
	autofillFiles := []string{"Login Data", "Web Data", "Login Data.db", "Web Data.db"}
	for _, name := range autofillFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := d.CopyFileArtifact(src, "chrome_autofill", "chrome"); err == nil {
			artifact.Category = "form_autofill"
			browser.FormAutofill = append(browser.FormAutofill, *artifact)
		}
	}

	// Cache
	cachePaths := []string{
		filepath.Join(profileDir, "Cache"),
		filepath.Join(profileDir, "Code Cache"),
		filepath.Join(profileDir, "GPUCache"),
	}
	for _, cachePath := range cachePaths {
		if _, err := d.OSStat(cachePath); err == nil {
			if artifact, err := d.CopyFileArtifact(cachePath, "chrome_cache", "chrome"); err == nil {
				artifact.Category = "cache"
				browser.Cache = append(browser.Cache, *artifact)
			}
		}
	}

	// Extensions
	extensionsDir := filepath.Join(profileDir, "Extensions")
	if entries, err := d.OSReadDir(extensionsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				extDir := filepath.Join(extensionsDir, entry.Name())
				if artifact, err := d.CopyFileArtifact(extDir, "chrome_ext", "chrome"); err == nil {
					artifact.Category = "chromium_extension"
					browser.ChromiumExtensions = append(browser.ChromiumExtensions, *artifact)
				}
			}
		}
	}

	// Preferences file (indicates a valid profile)
	prefFile := filepath.Join(profileDir, "Preferences")
	if _, err := d.OSStat(prefFile); err == nil {
		if artifact, err := d.CopyFileArtifact(prefFile, "chrome_prefs", "chrome"); err == nil {
			artifact.Category = "chromium_profile"
			browser.ChromiumProfiles = append(browser.ChromiumProfiles, *artifact)
		}
	}

	// Search history
	searchFiles := []string{"Search History", "Visited Links"}
	for _, name := range searchFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := d.CopyFileArtifact(src, "chrome_search", "chrome"); err == nil {
			artifact.Category = "search_history"
			browser.SearchHistory = append(browser.SearchHistory, *artifact)
		}
	}
}

// collectThunderbirdArtifacts collects Thunderbird email artifacts (shared by Linux and Darwin)
func (d *Default) collectThunderbirdArtifacts(profileDir string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := d.OSStat(profileDir); err != nil {
		return
	}

	// Mail directory
	mailDir := filepath.Join(profileDir, "Mail")
	if entries, err := d.OSReadDir(mailDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				mailboxPath := filepath.Join(mailDir, entry.Name())
				d.collectMailboxArtifacts(mailboxPath, comm, errors)
			}
		}
	}

	// ImapMail directory (remote mail)
	imapDir := filepath.Join(profileDir, "ImapMail")
	if entries, err := d.OSReadDir(imapDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				mailboxPath := filepath.Join(imapDir, entry.Name())
				d.collectMailboxArtifacts(mailboxPath, comm, errors)
			}
		}
	}
}

// collectMailboxArtifacts collects mailbox artifacts (MBOX files) - shared helper
func (d *Default) collectMailboxArtifacts(mailboxPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := d.OSStat(mailboxPath); err != nil {
		return
	}

	// Check if it's an mbox file
	files, err := filepath.Glob(filepath.Join(mailboxPath, "*.mbox"))
	if err == nil {
		for _, mboxFile := range files {
			filename := filepath.Base(mboxFile)
			lowerName := strings.ToLower(filename)

			var target *[]models.ForensicFile
			switch {
			case strings.Contains(lowerName, "draft"):
				target = &comm.Emails.Gmail.Drafts
			case strings.Contains(lowerName, "sent") || strings.Contains(lowerName, "outbox"):
				target = &comm.Emails.Gmail.Sent
			case strings.Contains(lowerName, "trash") || strings.Contains(lowerName, "deleted"):
				target = &comm.Emails.Gmail.Trash
			default:
				target = &comm.Emails.Default
			}

			if artifact, err := d.CopyFileArtifact(mboxFile, "mbox_"+filename, "thunderbird"); err == nil {
				artifact.Category = "email_default"
				*target = append(*target, *artifact)
			}
		}
	}
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
