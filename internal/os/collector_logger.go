// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"time"

	"github.com/ilexum-group/tracium/internal/utils"
	"github.com/ilexum-group/tracium/pkg/models"
)

// LoggingCollector wraps a Collector and automatically logs all method calls with timing
type LoggingCollector struct {
	collector Collector
	logFunc   models.CommandLogger
}

// NewLoggingCollector creates a new LoggingCollector that wraps the given collector
func NewLoggingCollector(collector Collector, logFunc models.CommandLogger) Collector {
	// Set the logger on the underlying collector as well
	collector.SetLogger(logFunc)
	return &LoggingCollector{
		collector: collector,
		logFunc:   logFunc,
	}
}

// logMethodCall logs a method invocation with timing
func (lc *LoggingCollector) logMethodCall(methodName string, args []string, fn func() error) error {
	if lc.logFunc == nil {
		return fn()
	}

	startTime := time.Now()
	err := fn()
	endTime := time.Now()

	exitCode := 0
	if err != nil {
		exitCode = 1
	}

	lc.logFunc(utils.GenerateRandomID(), methodName, args, startTime, endTime, exitCode, err, "", "")
	return err
}

// SetLogger configures the logging function
func (lc *LoggingCollector) SetLogger(logFunc models.CommandLogger) {
	lc.logFunc = logFunc
	lc.collector.SetLogger(logFunc)
}

// OSName returns the detected OS name
func (lc *LoggingCollector) OSName() string {
	var result string
	_ = lc.logMethodCall("OSName", []string{}, func() error {
		result = lc.collector.OSName()
		return nil
	})
	return result
}

// Architecture returns the detected CPU architecture
func (lc *LoggingCollector) Architecture() string {
	var result string
	_ = lc.logMethodCall("Architecture", []string{}, func() error {
		result = lc.collector.Architecture()
		return nil
	})
	return result
}

// Hostname returns the system hostname
func (lc *LoggingCollector) Hostname() (string, error) {
	var result string
	var err error
	_ = lc.logMethodCall("Hostname", []string{}, func() error {
		result, err = lc.collector.Hostname()
		return err
	})
	return result, err
}

// GetCurrentUser retrieves the current executing user
func (lc *LoggingCollector) GetCurrentUser() (string, error) {
	var result string
	var err error
	_ = lc.logMethodCall("GetCurrentUser", []string{}, func() error {
		result, err = lc.collector.GetCurrentUser()
		return err
	})
	return result, err
}

// GetProcessID returns the current process ID
func (lc *LoggingCollector) GetProcessID() int {
	var result int
	_ = lc.logMethodCall("GetProcessID", []string{}, func() error {
		result = lc.collector.GetProcessID()
		return nil
	})
	return result
}

// GetUptime returns the system uptime in seconds
func (lc *LoggingCollector) GetUptime() int64 {
	var result int64
	_ = lc.logMethodCall("GetUptime", []string{}, func() error {
		result = lc.collector.GetUptime()
		return nil
	})
	return result
}

// GetUsers returns the list of system users
func (lc *LoggingCollector) GetUsers() []string {
	var result []string
	_ = lc.logMethodCall("GetUsers", []string{}, func() error {
		result = lc.collector.GetUsers()
		return nil
	})
	return result
}

// GetCPUInfo returns CPU information
func (lc *LoggingCollector) GetCPUInfo() models.CPUInfo {
	var result models.CPUInfo
	_ = lc.logMethodCall("GetCPUInfo", []string{}, func() error {
		result = lc.collector.GetCPUInfo()
		return nil
	})
	return result
}

// GetMemoryInfo returns memory information
func (lc *LoggingCollector) GetMemoryInfo() models.MemoryInfo {
	var result models.MemoryInfo
	_ = lc.logMethodCall("GetMemoryInfo", []string{}, func() error {
		result = lc.collector.GetMemoryInfo()
		return nil
	})
	return result
}

// GetDiskInfo returns disk information
func (lc *LoggingCollector) GetDiskInfo() []models.DiskInfo {
	var result []models.DiskInfo
	_ = lc.logMethodCall("GetDiskInfo", []string{}, func() error {
		result = lc.collector.GetDiskInfo()
		return nil
	})
	return result
}

// GetInterfaces returns network interfaces
func (lc *LoggingCollector) GetInterfaces() []models.InterfaceInfo {
	var result []models.InterfaceInfo
	_ = lc.logMethodCall("GetInterfaces", []string{}, func() error {
		result = lc.collector.GetInterfaces()
		return nil
	})
	return result
}

// GetListeningPorts returns listening ports
func (lc *LoggingCollector) GetListeningPorts(seen map[int]bool) []int {
	var result []int
	_ = lc.logMethodCall("GetListeningPorts", []string{}, func() error {
		result = lc.collector.GetListeningPorts(seen)
		return nil
	})
	return result
}

// GetProcesses returns running processes
func (lc *LoggingCollector) GetProcesses() []models.ProcessInfo {
	var result []models.ProcessInfo
	_ = lc.logMethodCall("GetProcesses", []string{}, func() error {
		result = lc.collector.GetProcesses()
		return nil
	})
	return result
}

// GetServices returns system services
func (lc *LoggingCollector) GetServices() []models.ServiceInfo {
	var result []models.ServiceInfo
	_ = lc.logMethodCall("GetServices", []string{}, func() error {
		result = lc.collector.GetServices()
		return nil
	})
	return result
}

// CollectBrowserDBFiles collects browser database files
func (lc *LoggingCollector) CollectBrowserDBFiles(errors *[]string) []models.ForensicFile {
	var result []models.ForensicFile
	_ = lc.logMethodCall("CollectBrowserDBFiles", []string{}, func() error {
		result = lc.collector.CollectBrowserDBFiles(errors)
		return nil
	})
	return result
}

// CollectRecentFiles collects recently accessed files
func (lc *LoggingCollector) CollectRecentFiles(errors *[]string) []models.RecentFileEntry {
	var result []models.RecentFileEntry
	_ = lc.logMethodCall("CollectRecentFiles", []string{}, func() error {
		result = lc.collector.CollectRecentFiles(errors)
		return nil
	})
	return result
}

// CollectCommandHistory collects shell command history
func (lc *LoggingCollector) CollectCommandHistory(errors *[]string) []models.CommandEntry {
	var result []models.CommandEntry
	_ = lc.logMethodCall("CollectCommandHistory", []string{}, func() error {
		result = lc.collector.CollectCommandHistory(errors)
		return nil
	})
	return result
}

// CollectNetworkHistory collects network connection history
func (lc *LoggingCollector) CollectNetworkHistory(errors *[]string) models.NetworkHistoryData {
	var result models.NetworkHistoryData
	_ = lc.logMethodCall("CollectNetworkHistory", []string{}, func() error {
		result = lc.collector.CollectNetworkHistory(errors)
		return nil
	})
	return result
}

// CollectSystemLogs collects system log files
func (lc *LoggingCollector) CollectSystemLogs(errors *[]string) []models.LogFile {
	var result []models.LogFile
	_ = lc.logMethodCall("CollectSystemLogs", []string{}, func() error {
		result = lc.collector.CollectSystemLogs(errors)
		return nil
	})
	return result
}

// CollectScheduledTasks collects scheduled tasks
func (lc *LoggingCollector) CollectScheduledTasks(errors *[]string) []models.ScheduledTask {
	var result []models.ScheduledTask
	_ = lc.logMethodCall("CollectScheduledTasks", []string{}, func() error {
		result = lc.collector.CollectScheduledTasks(errors)
		return nil
	})
	return result
}

// CollectActiveConnections collects active network connections
func (lc *LoggingCollector) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	var result []models.NetworkConnection
	_ = lc.logMethodCall("CollectActiveConnections", []string{}, func() error {
		result = lc.collector.CollectActiveConnections(errors)
		return nil
	})
	return result
}

// CollectHostsFile collects the hosts file
func (lc *LoggingCollector) CollectHostsFile(errors *[]string) *models.ForensicFile {
	var result *models.ForensicFile
	_ = lc.logMethodCall("CollectHostsFile", []string{}, func() error {
		result = lc.collector.CollectHostsFile(errors)
		return nil
	})
	return result
}

// CollectSSHKeys collects SSH key information
func (lc *LoggingCollector) CollectSSHKeys(errors *[]string) []models.SSHKeyInfo {
	var result []models.SSHKeyInfo
	_ = lc.logMethodCall("CollectSSHKeys", []string{}, func() error {
		result = lc.collector.CollectSSHKeys(errors)
		return nil
	})
	return result
}

// CollectInstalledSoftware collects installed software information
func (lc *LoggingCollector) CollectInstalledSoftware(errors *[]string) []models.SoftwareInfo {
	var result []models.SoftwareInfo
	_ = lc.logMethodCall("CollectInstalledSoftware", []string{}, func() error {
		result = lc.collector.CollectInstalledSoftware(errors)
		return nil
	})
	return result
}

// CollectEnvironmentVariables collects environment variables
func (lc *LoggingCollector) CollectEnvironmentVariables(errors *[]string) map[string]string {
	var result map[string]string
	_ = lc.logMethodCall("CollectEnvironmentVariables", []string{}, func() error {
		result = lc.collector.CollectEnvironmentVariables(errors)
		return nil
	})
	return result
}

// CollectRecentDownloads collects recently downloaded files
func (lc *LoggingCollector) CollectRecentDownloads(errors *[]string) []models.RecentFileEntry {
	var result []models.RecentFileEntry
	_ = lc.logMethodCall("CollectRecentDownloads", []string{}, func() error {
		result = lc.collector.CollectRecentDownloads(errors)
		return nil
	})
	return result
}

// CollectUSBHistory collects USB device connection history
func (lc *LoggingCollector) CollectUSBHistory(errors *[]string) []models.USBDevice {
	var result []models.USBDevice
	_ = lc.logMethodCall("CollectUSBHistory", []string{}, func() error {
		result = lc.collector.CollectUSBHistory(errors)
		return nil
	})
	return result
}

// CollectPrefetchFiles collects Windows prefetch information
func (lc *LoggingCollector) CollectPrefetchFiles(errors *[]string) []models.PrefetchInfo {
	var result []models.PrefetchInfo
	_ = lc.logMethodCall("CollectPrefetchFiles", []string{}, func() error {
		result = lc.collector.CollectPrefetchFiles(errors)
		return nil
	})
	return result
}

// CollectRecycleBin collects recycle bin contents
func (lc *LoggingCollector) CollectRecycleBin(errors *[]string) []models.DeletedFile {
	var result []models.DeletedFile
	_ = lc.logMethodCall("CollectRecycleBin", []string{}, func() error {
		result = lc.collector.CollectRecycleBin(errors)
		return nil
	})
	return result
}

// CollectClipboard collects current clipboard content
func (lc *LoggingCollector) CollectClipboard(errors *[]string) string {
	var result string
	_ = lc.logMethodCall("CollectClipboard", []string{}, func() error {
		result = lc.collector.CollectClipboard(errors)
		return nil
	})
	return result
}

// System Primitives wrappers

// OSReadFile wraps os.ReadFile with logging
func (lc *LoggingCollector) OSReadFile(path string) ([]byte, error) {
	var result []byte
	var err error
	_ = lc.logMethodCall("os.ReadFile", []string{path}, func() error {
		result, err = lc.collector.OSReadFile(path)
		return err
	})
	return result, err
}

// OSOpen wraps os.Open with logging
func (lc *LoggingCollector) OSOpen(path string) (*os.File, error) {
	var result *os.File
	var err error
	_ = lc.logMethodCall("os.Open", []string{path}, func() error {
		result, err = lc.collector.OSOpen(path)
		return err
	})
	return result, err
}

// OSStat wraps os.Stat with logging
func (lc *LoggingCollector) OSStat(path string) (fs.FileInfo, error) {
	var result fs.FileInfo
	var err error
	_ = lc.logMethodCall("os.Stat", []string{path}, func() error {
		result, err = lc.collector.OSStat(path)
		return err
	})
	return result, err
}

// OSReadDir wraps os.ReadDir with logging
func (lc *LoggingCollector) OSReadDir(path string) ([]fs.DirEntry, error) {
	var result []fs.DirEntry
	var err error
	_ = lc.logMethodCall("os.ReadDir", []string{path}, func() error {
		result, err = lc.collector.OSReadDir(path)
		return err
	})
	return result, err
}

// OSCreate wraps os.Create with logging
func (lc *LoggingCollector) OSCreate(path string) (*os.File, error) {
	var result *os.File
	var err error
	_ = lc.logMethodCall("os.Create", []string{path}, func() error {
		result, err = lc.collector.OSCreate(path)
		return err
	})
	return result, err
}

// OSUserHomeDir wraps os.UserHomeDir with logging
func (lc *LoggingCollector) OSUserHomeDir() (string, error) {
	var result string
	var err error
	_ = lc.logMethodCall("os.UserHomeDir", []string{}, func() error {
		result, err = lc.collector.OSUserHomeDir()
		return err
	})
	return result, err
}

// OSUserHomeDirs wraps OSUserHomeDirs with logging
func (lc *LoggingCollector) OSUserHomeDirs() ([]string, error) {
	var result []string
	var err error
	_ = lc.logMethodCall("os.UserHomeDirs", []string{}, func() error {
		result, err = lc.collector.OSUserHomeDirs()
		return err
	})
	return result, err
}

// CollectFilesystemTree wraps CollectFilesystemTree with logging
func (lc *LoggingCollector) CollectFilesystemTree() models.FilesystemTree {
	var result models.FilesystemTree
	_ = lc.logMethodCall("CollectFilesystemTree", []string{}, func() error {
		result = lc.collector.CollectFilesystemTree()
		return nil
	})
	return result
}

// OSGetenv wraps os.Getenv with logging
func (lc *LoggingCollector) OSGetenv(key string) string {
	var result string
	_ = lc.logMethodCall("os.Getenv", []string{key}, func() error {
		result = lc.collector.OSGetenv(key)
		return nil
	})
	return result
}

// UserCurrent wraps user.Current with logging
func (lc *LoggingCollector) UserCurrent() (*user.User, error) {
	var result *user.User
	var err error
	_ = lc.logMethodCall("user.Current", []string{}, func() error {
		result, err = lc.collector.UserCurrent()
		return err
	})
	return result, err
}

// UserLookupID wraps user.LookupId with logging
func (lc *LoggingCollector) UserLookupID(uid string) (*user.User, error) {
	var result *user.User
	var err error
	_ = lc.logMethodCall("user.LookupId", []string{uid}, func() error {
		result, err = lc.collector.UserLookupID(uid)
		return err
	})
	return result, err
}

// ExecCommand wraps exec.Command with logging
func (lc *LoggingCollector) ExecCommand(name string, args ...string) *exec.Cmd {
	var result *exec.Cmd
	allArgs := append([]string{name}, args...)
	_ = lc.logMethodCall("exec.Command", allArgs, func() error {
		result = lc.collector.ExecCommand(name, args...)
		return nil
	})
	return result
}

// NetInterfaces wraps net.Interfaces with logging
func (lc *LoggingCollector) NetInterfaces() ([]net.Interface, error) {
	var result []net.Interface
	var err error
	_ = lc.logMethodCall("net.Interfaces", []string{}, func() error {
		result, err = lc.collector.NetInterfaces()
		return err
	})
	return result, err
}
