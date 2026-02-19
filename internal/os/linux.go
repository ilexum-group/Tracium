// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ilexum-group/tracium/pkg/models"
)

// Linux implements Collector for Linux systems
type Linux struct {
	*Default
}

// NewLinux creates a new Linux instance
func NewLinux() Collector {
	return NewLinuxWithDefault(NewDefault())
}

// NewLinuxWithDefault creates a new Linux instance with a provided Default.
func NewLinuxWithDefault(def *Default) Collector {
	return &Linux{
		Default: def,
	}
}

// GetCurrentUser returns the current user name
func (l *Linux) GetCurrentUser() (string, error) {
	if !l.IsLive() {
		return "unknown", nil
	}
	currentUser, err := l.UserCurrent()
	if err != nil {
		return "", err
	}
	return currentUser.Username, nil
}

// GetUptime returns the system uptime in seconds
func (l *Linux) GetUptime() int64 {
	data, err := l.OSReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	parts := strings.Fields(string(data))
	if len(parts) > 0 {
		uptimeFloat, err := strconv.ParseFloat(parts[0], 64)
		if err == nil {
			return int64(uptimeFloat)
		}
	}
	return 0
}

// GetUsers returns the list of system users
func (l *Linux) GetUsers() []string {
	var users []string

	file, err := l.OSOpen("/etc/passwd")
	if err != nil {
		// Fallback to current user
		if currentUser, err := l.UserCurrent(); err == nil {
			return []string{currentUser.Username}
		}
		return users
	}
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

	return users
}

// GetCPUInfo returns CPU information
func (l *Linux) GetCPUInfo() models.CPUInfo {
	cpuInfo := models.CPUInfo{
		Cores: 0,
		Model: "Unknown",
	}

	data, err := l.OSReadFile("/proc/cpuinfo")
	if err != nil {
		return cpuInfo
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	processorCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "processor") {
			processorCount++
		} else if strings.HasPrefix(line, "model name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				cpuInfo.Model = strings.TrimSpace(parts[1])
			}
		}
	}

	cpuInfo.Cores = processorCount
	return cpuInfo
}

// GetMemoryInfo returns memory information
func (l *Linux) GetMemoryInfo() models.MemoryInfo {
	memInfo := models.MemoryInfo{}

	data, err := l.OSReadFile("/proc/meminfo")
	if err != nil {
		return memInfo
	}

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

	return memInfo
}

// GetDiskInfo returns disk information
func (l *Linux) GetDiskInfo() []models.DiskInfo {
	var disks []models.DiskInfo
	if !l.IsLive() {
		return disks
	}
	data, err := l.OSReadFile("/proc/mounts")
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

			if total, used, ok := getLinuxDiskUsage(mountPoint); ok {

				disks = append(disks, models.DiskInfo{
					Path:       mountPoint,
					Total:      total,
					Used:       used,
					FileSystem: fsType,
				})
			}
		}
	}

	return disks
}

// GetListeningPorts returns listening ports
func (l *Linux) GetListeningPorts(seen map[int]bool) []int {
	var ports []int

	// Parse /proc/net/tcp and /proc/net/tcp6
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		//nolint:gosec // G304: /proc files are trusted system paths
		data, err := l.OSReadFile(file)
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
		data, err := l.OSReadFile(file)
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

// GetProcesses returns running processes
func (l *Linux) GetProcesses() []models.ProcessInfo {
	var processes []models.ProcessInfo
	entries, err := l.OSReadDir("/proc")
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

		procInfo := models.ProcessInfo{PID: pid}

		// Get command name
		cmdline, err := l.OSReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && len(cmdline) > 0 {
			parts := bytes.Split(cmdline, []byte{0})
			if len(parts) > 0 {
				procInfo.Name = filepath.Base(string(parts[0]))
			}
		}

		// Get status info
		status, err := l.OSReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(status))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						uid := fields[1]
						if l.IsLive() {
							if u, err := l.UserLookupID(uid); err == nil {
								procInfo.User = u.Username
							} else {
								procInfo.User = uid
							}
						} else {
							procInfo.User = uid
						}
					}
				} else if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						mem, _ := strconv.ParseUint(fields[1], 10, 64)
						procInfo.Memory = mem * 1024
					}
				}
			}
		}

		// Get CPU usage
		stat, err := l.OSReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err == nil {
			fields := strings.Fields(string(stat))
			if len(fields) > 13 {
				utime, _ := strconv.ParseUint(fields[13], 10, 64)
				stime, _ := strconv.ParseUint(fields[14], 10, 64)
				totalTime := float64(utime + stime)
				procInfo.CPU = totalTime / 100.0
			}
		}

		if procInfo.Name != "" {
			processes = append(processes, procInfo)
		}
	}

	return processes
}

// GetServices returns system services
func (l *Linux) GetServices() []models.ServiceInfo {
	var services []models.ServiceInfo

	serviceDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
		"/etc/init.d",
	}

	seen := make(map[string]bool)
	count := 0

	for _, dir := range serviceDirs {
		entries, err := l.OSReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".service") {
				name = strings.TrimSuffix(name, ".service")
			}
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			services = append(services, models.ServiceInfo{
				Name:        name,
				Status:      "unknown",
				Description: "",
			})
			count++
		}
	}

	return services
}

// Forensics methods implementation for Linux

// CollectBrowserArtifacts collects structured browser artifacts
func (l *Linux) CollectBrowserArtifacts(errors *[]string) models.BrowserArtifacts {
	browser := models.BrowserArtifacts{
		ChromiumProfiles:   make([]models.ForensicFile, 0),
		ChromiumExtensions: make([]models.ForensicFile, 0),
		Bookmarks:          make([]models.ForensicFile, 0),
		Cache:              make([]models.ForensicFile, 0),
		Cookies:            make([]models.ForensicFile, 0),
		Downloads:          make([]models.ForensicFile, 0),
		FormAutofill:       make([]models.ForensicFile, 0),
		History:            make([]models.ForensicFile, 0),
		SearchHistory:      make([]models.ForensicFile, 0),
	}

	homeDirs, err := l.OSUserHomeDirs()
	if err != nil {
		return browser
	}

	for _, homeDir := range homeDirs {
		// Chrome/Chromium
		chromeBase := filepath.Join(homeDir, ".config", "google-chrome")
		if entries, err := l.OSReadDir(chromeBase); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				profileDir := filepath.Join(chromeBase, entry.Name())
				l.collectChromeProfileArtifacts(profileDir, &browser, errors)
			}
		}

		// Also check Default profile
		defaultChrome := filepath.Join(homeDir, ".config", "google-chrome", "Default")
		l.collectChromeProfileArtifacts(defaultChrome, &browser, errors)

		// Chromium (e.g., Brave, Edge)
		chromiumPaths := []string{
			filepath.Join(homeDir, ".config", "chromium"),
			filepath.Join(homeDir, ".config", "BraveSoftware"),
			filepath.Join(homeDir, ".config", "microsoft-edge"),
		}
		for _, chromiumPath := range chromiumPaths {
			if entries, err := l.OSReadDir(chromiumPath); err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					profileDir := filepath.Join(chromiumPath, entry.Name())
					l.collectChromeProfileArtifacts(profileDir, &browser, errors)
				}
			}
		}

		// Firefox
		firefoxProfiles := filepath.Join(homeDir, ".mozilla", "firefox")
		if profiles, err := filepath.Glob(filepath.Join(firefoxProfiles, "*.default*")); err == nil {
			for _, profile := range profiles {
				l.collectFirefoxArtifacts(profile, &browser, errors)
			}
		}

		// Opera
		operaBase := filepath.Join(homeDir, ".config", "opera")
		l.collectChromeProfileArtifacts(operaBase, &browser, errors)
	}

	return browser
}

// collectChromeProfileArtifacts collects artifacts from a Chrome/Chromium profile directory
func (l *Linux) collectChromeProfileArtifacts(profileDir string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := l.OSStat(profileDir); err != nil {
		return
	}

	// History
	historyFiles := []string{"History", "History.db"}
	for _, name := range historyFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := l.CopyFileArtifact(src, "chrome_history", "chrome"); err == nil {
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
		if artifact, err := l.CopyFileArtifact(src, "chrome_cookies", "chrome"); err == nil {
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
		if artifact, err := l.CopyFileArtifact(src, "chrome_downloads", "chrome"); err == nil {
			artifact.Category = "downloads"
			browser.Downloads = append(browser.Downloads, *artifact)
		}
	}

	// Bookmarks
	src := filepath.Join(profileDir, "Bookmarks")
	if artifact, err := l.CopyFileArtifact(src, "chrome_bookmarks", "chrome"); err == nil {
		artifact.Category = "bookmarks"
		browser.Bookmarks = append(browser.Bookmarks, *artifact)
	}

	// Login/Autofill
	autofillFiles := []string{"Login Data", "Web Data", "Login Data.db", "Web Data.db"}
	for _, name := range autofillFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := l.CopyFileArtifact(src, "chrome_autofill", "chrome"); err == nil {
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
		if _, err := l.OSStat(cachePath); err == nil {
			if artifact, err := l.CopyFileArtifact(cachePath, "chrome_cache", "chrome"); err == nil {
				artifact.Category = "cache"
				browser.Cache = append(browser.Cache, *artifact)
			}
		}
	}

	// Extensions
	extensionsDir := filepath.Join(profileDir, "Extensions")
	if entries, err := l.OSReadDir(extensionsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				extDir := filepath.Join(extensionsDir, entry.Name())
				if artifact, err := l.CopyFileArtifact(extDir, "chrome_ext", "chrome"); err == nil {
					artifact.Category = "chromium_extension"
					browser.ChromiumExtensions = append(browser.ChromiumExtensions, *artifact)
				}
			}
		}
	}

	// Preferences file (indicates a valid profile)
	prefFile := filepath.Join(profileDir, "Preferences")
	if _, err := l.OSStat(prefFile); err == nil {
		if artifact, err := l.CopyFileArtifact(prefFile, "chrome_prefs", "chrome"); err == nil {
			artifact.Category = "chromium_profile"
			browser.ChromiumProfiles = append(browser.ChromiumProfiles, *artifact)
		}
	}

	// Search history
	searchFiles := []string{"Search History", "Visited Links"}
	for _, name := range searchFiles {
		src := filepath.Join(profileDir, name)
		if artifact, err := l.CopyFileArtifact(src, "chrome_search", "chrome"); err == nil {
			artifact.Category = "search_history"
			browser.SearchHistory = append(browser.SearchHistory, *artifact)
		}
	}
}

// collectFirefoxArtifacts collects artifacts from a Firefox profile directory
func (l *Linux) collectFirefoxArtifacts(profileDir string, browser *models.BrowserArtifacts, errors *[]string) {
	if _, err := l.OSStat(profileDir); err != nil {
		return
	}

	// History (places.sqlite)
	src := filepath.Join(profileDir, "places.sqlite")
	if artifact, err := l.CopyFileArtifact(src, "firefox_places", "firefox"); err == nil {
		artifact.Category = "history"
		browser.History = append(browser.History, *artifact)
	} else if errors != nil && !strings.Contains(err.Error(), "artifact missing") {
		*errors = append(*errors, err.Error())
	}

	// Cookies
	src = filepath.Join(profileDir, "cookies.sqlite")
	if artifact, err := l.CopyFileArtifact(src, "firefox_cookies", "firefox"); err == nil {
		artifact.Category = "cookies"
		browser.Cookies = append(browser.Cookies, *artifact)
	}

	// Downloads
	src = filepath.Join(profileDir, "downloads.sqlite")
	if artifact, err := l.CopyFileArtifact(src, "firefox_downloads", "firefox"); err == nil {
		artifact.Category = "downloads"
		browser.Downloads = append(browser.Downloads, *artifact)
	}

	// Bookmarks
	src = filepath.Join(profileDir, "bookmarks.sqlite")
	if artifact, err := l.CopyFileArtifact(src, "firefox_bookmarks", "firefox"); err == nil {
		artifact.Category = "bookmarks"
		browser.Bookmarks = append(browser.Bookmarks, *artifact)
	}

	// Form history
	src = filepath.Join(profileDir, "formhistory.sqlite")
	if artifact, err := l.CopyFileArtifact(src, "firefox_formhistory", "firefox"); err == nil {
		artifact.Category = "form_autofill"
		browser.FormAutofill = append(browser.FormAutofill, *artifact)
	}

	// Cache
	cacheDir := filepath.Join(profileDir, "cache2")
	if _, err := l.OSStat(cacheDir); err == nil {
		if artifact, err := l.CopyFileArtifact(cacheDir, "firefox_cache", "firefox"); err == nil {
			artifact.Category = "cache"
			browser.Cache = append(browser.Cache, *artifact)
		}
	}

	// Search history
	src = filepath.Join(profileDir, "search.sqlite")
	if artifact, err := l.CopyFileArtifact(src, "firefox_search", "firefox"); err == nil {
		artifact.Category = "search_history"
		browser.SearchHistory = append(browser.SearchHistory, *artifact)
	}

	// Extensions
	extensionsDir := filepath.Join(profileDir, "extensions")
	if entries, err := l.OSReadDir(extensionsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			extDir := filepath.Join(extensionsDir, entry.Name())
			if artifact, err := l.CopyFileArtifact(extDir, "firefox_ext", "firefox"); err == nil {
				artifact.Category = "chromium_extension"
				browser.ChromiumExtensions = append(browser.ChromiumExtensions, *artifact)
			}
		}
	}
}

// CollectCommunicationArtifacts collects communication artifacts (email, chat, etc.)
func (l *Linux) CollectCommunicationArtifacts(errors *[]string) models.CommunicationArtifacts {
	comm := models.CommunicationArtifacts{
		Accounts: make([]models.ForensicFile, 0),
		Emails: models.EmailArtifacts{
			Default: make([]models.ForensicFile, 0),
			Gmail: models.GmailFolders{
				Drafts: make([]models.ForensicFile, 0),
				Sent:   make([]models.ForensicFile, 0),
				Trash:  make([]models.ForensicFile, 0),
			},
		},
	}

	homeDirs, err := l.OSUserHomeDirs()
	if err != nil {
		return comm
	}

	for _, homeDir := range homeDirs {
		// Thunderbird (Linux email client)
		thunderbirdPath := filepath.Join(homeDir, ".thunderbird")
		if profiles, err := filepath.Glob(filepath.Join(thunderbirdPath, "*.default*")); err == nil {
			for _, profile := range profiles {
				l.collectThunderbirdArtifacts(profile, &comm, errors)
			}
		}

		// Claws Mail
		clawsPath := filepath.Join(homeDir, ".claws-mail")
		if _, err := l.OSStat(clawsPath); err == nil {
			l.collectClawsMailArtifacts(clawsPath, &comm, errors)
		}

		// KMail
		kmailPath := filepath.Join(homeDir, ".local/share", "kmail2")
		if _, err := l.OSStat(kmailPath); err == nil {
			l.collectKMailArtifacts(kmailPath, &comm, errors)
		}

		// Evolution
		evolutionPath := filepath.Join(homeDir, ".local/share/evolution")
		if _, err := l.OSStat(evolutionPath); err == nil {
			l.collectEvolutionArtifacts(evolutionPath, &comm, errors)
		}

		// Email account configurations
		accountFiles := []string{
			filepath.Join(homeDir, ".config", "evolution", "sources"),
			filepath.Join(homeDir, ".thunderbird", "profiles.ini"),
		}
		for _, accountFile := range accountFiles {
			if _, err := l.OSStat(accountFile); err == nil {
				if artifact, err := l.CopyFileArtifact(accountFile, "email_account", "thunderbird"); err == nil {
					artifact.Category = "email_account"
					comm.Accounts = append(comm.Accounts, *artifact)
				}
			}
		}
	}

	return comm
}

// collectThunderbirdArtifacts collects Thunderbird email artifacts
func (l *Linux) collectThunderbirdArtifacts(profileDir string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := l.OSStat(profileDir); err != nil {
		return
	}

	// Mail directory
	mailDir := filepath.Join(profileDir, "Mail")
	if entries, err := l.OSReadDir(mailDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				mailboxPath := filepath.Join(mailDir, entry.Name())
				l.collectMailboxArtifacts(mailboxPath, comm, errors)
			}
		}
	}

	// ImapMail directory (remote mail)
	imapDir := filepath.Join(profileDir, "ImapMail")
	if entries, err := l.OSReadDir(imapDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				mailboxPath := filepath.Join(imapDir, entry.Name())
				l.collectMailboxArtifacts(mailboxPath, comm, errors)
			}
		}
	}
}

// collectMailboxArtifacts collects mailbox artifacts (MBOX files)
func (l *Linux) collectMailboxArtifacts(mailboxPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	if _, err := l.OSStat(mailboxPath); err != nil {
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

			if artifact, err := l.CopyFileArtifact(mboxFile, "mbox_"+filename, "thunderbird"); err == nil {
				artifact.Category = "email_default"
				*target = append(*target, *artifact)
			}
		}
	}
}

// collectClawsMailArtifacts collects Claws Mail artifacts
func (l *Linux) collectClawsMailArtifacts(clawsPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	// Claws Mail folder tree
	folderPath := filepath.Join(clawsPath, "folder树")
	if _, err := l.OSStat(folderPath); err == nil {
		if artifact, err := l.CopyFileArtifact(folderPath, "claws_folder", "claws-mail"); err == nil {
			artifact.Category = "email_account"
			comm.Accounts = append(comm.Accounts, *artifact)
		}
	}

	// MBox files
	mailPath := filepath.Join(clawsPath, "Mail")
	if entries, err := l.OSReadDir(mailPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			mboxDir := filepath.Join(mailPath, entry.Name())
			l.collectMailboxArtifacts(mboxDir, comm, errors)
		}
	}
}

// collectKMailArtifacts collects KMail artifacts
func (l *Linux) collectKMailArtifacts(kmailPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	// KMail stores mail in maildir format
	if entries, err := l.OSReadDir(kmailPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				maildirPath := filepath.Join(kmailPath, entry.Name())
				if artifact, err := l.CopyFileArtifact(maildirPath, "kmail_"+entry.Name(), "kmail"); err == nil {
					artifact.Category = "email_default"
					comm.Emails.Default = append(comm.Emails.Default, *artifact)
				}
			}
		}
	}
}

// collectEvolutionArtifacts collects Evolution email artifacts
func (l *Linux) collectEvolutionArtifacts(evolutionPath string, comm *models.CommunicationArtifacts, errors *[]string) {
	// Evolution mail storage
	mailDir := filepath.Join(evolutionPath, "mail")
	if entries, err := l.OSReadDir(mailDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				mboxPath := filepath.Join(mailDir, entry.Name())
				if artifact, err := l.CopyFileArtifact(mboxPath, "evolution_"+entry.Name(), "evolution"); err == nil {
					artifact.Category = "email_default"
					comm.Emails.Default = append(comm.Emails.Default, *artifact)
				}
			}
		}
	}
}

// CollectRecentFiles collects recently accessed files
func (l *Linux) CollectRecentFiles(_ *[]string) []models.RecentFileEntry {
	files := make([]models.RecentFileEntry, 0)
	homeDirs, err := l.OSUserHomeDirs()
	if err != nil {
		return files
	}

	for _, homeDir := range homeDirs {
		recentPath := filepath.Join(homeDir, ".local", "share", "recently-used.xbel")
		if _, err := l.OSStat(recentPath); err == nil {
			files = append(files, models.RecentFileEntry{
				FilePath:     recentPath,
				FileName:     "recently-used.xbel",
				AccessedTime: time.Now().Unix(),
				Source:       "xbel",
			})
		}
	}

	return files
}

// CollectCommandHistory collects shell command history
//
//nolint:dupl // Similar Unix shell history collection, platform-specific behavior
func (l *Linux) CollectCommandHistory(_ *[]string) []models.CommandEntry {
	commands := make([]models.CommandEntry, 0)
	homeDirs, err := l.OSUserHomeDirs()
	if err != nil {
		return commands
	}

	for _, homeDir := range homeDirs {
		// Bash history
		historyPath := filepath.Join(homeDir, ".bash_history")
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := l.OSReadFile(historyPath); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					commands = append(commands, models.CommandEntry{
						Shell:   "bash",
						Command: line,
						LineNum: i + 1,
					})
				}
			}
		}

		// Zsh history
		historyPath = filepath.Join(homeDir, ".zsh_history")
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := l.OSReadFile(historyPath); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					if strings.Contains(line, ";") {
						if parts := strings.SplitN(line, ";", 2); len(parts) == 2 {
							line = parts[1]
						}
					}
					commands = append(commands, models.CommandEntry{
						Shell:   "zsh",
						Command: line,
						LineNum: i + 1,
					})
				}
			}
		}

		// Fish history
		historyPath = filepath.Join(homeDir, ".local", "share", "fish", "fish_history")
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := l.OSReadFile(historyPath); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "- cmd:") {
					cmd := strings.TrimSpace(strings.TrimPrefix(line, "- cmd:"))
					if cmd != "" {
						commands = append(commands, models.CommandEntry{
							Shell:   "fish",
							Command: cmd,
							LineNum: i + 1,
						})
					}
				}
			}
		}

		// sh history
		historyPath = filepath.Join(homeDir, ".sh_history")
		//nolint:gosec // G304: path constructed from trusted UserHomeDir
		if content, err := l.OSReadFile(historyPath); err == nil {
			for i, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					commands = append(commands, models.CommandEntry{
						Shell:   "sh",
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
func (l *Linux) CollectNetworkHistory(_ *[]string) models.NetworkHistoryData {
	return models.NetworkHistoryData{
		ARPCache: l.CollectARPCacheUnix(),
		DNSCache: make([]models.DNSEntry, 0), // Linux doesn't have standard DNS cache
	}
}

// CollectSystemLogs collects system log files
func (l *Linux) CollectSystemLogs(errors *[]string) []models.LogFile {
	logs := make([]models.LogFile, 0)
	maxLogSize := int64(1024 * 1024)

	logPaths := []string{
		"/var/log/syslog",
		"/var/log/auth.log",
		"/var/log/kern.log",
		"/var/log/messages",
		"/var/log/secure",
	}

	for _, logPath := range logPaths {
		info, err := l.OSStat(logPath)
		if err != nil {
			continue
		}

		content, truncated, err := l.ReadFileWithLimit(logPath, maxLogSize)
		if err != nil {
			if errors != nil {
				*errors = append(*errors, fmt.Sprintf("failed to read log %s: %v", logPath, err))
			}
			continue
		}

		logs = append(logs, models.LogFile{
			Name:      filepath.Base(logPath),
			Path:      logPath,
			Size:      info.Size(),
			Content:   content,
			Truncated: truncated,
		})
	}

	logs = append(logs, collectJournaldLogs(l)...)

	return logs
}

func collectJournaldLogs(collector SystemPrimitives) []models.LogFile {
	logs := make([]models.LogFile, 0)
	base := "/var/log/journal"
	entries, err := collector.OSReadDir(base)
	if err != nil {
		return logs
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(base, entry.Name())
		files, err := collector.OSReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".journal") {
				continue
			}
			filePath := filepath.Join(dirPath, file.Name())
			if info, err := collector.OSStat(filePath); err == nil {
				logs = append(logs, models.LogFile{
					Name:      file.Name(),
					Path:      filePath,
					Size:      info.Size(),
					Content:   "",
					Truncated: false,
				})
			}
		}
	}
	return logs
}

// CollectScheduledTasks collects scheduled tasks and cron jobs
func (l *Linux) CollectScheduledTasks(_ *[]string) []models.ScheduledTask {
	tasks := make([]models.ScheduledTask, 0)

	parseCron := func(content []byte, user string) {
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if parts := strings.Fields(line); len(parts) >= 6 {
				tasks = append(tasks, models.ScheduledTask{
					Name:     strings.Join(parts[5:], " "),
					Command:  strings.Join(parts[5:], " "),
					Schedule: strings.Join(parts[0:5], " "),
					User:     user,
					Enabled:  true,
					Source:   "crontab",
				})
			}
		}
	}

	// System crontab
	if data, err := l.OSReadFile("/etc/crontab"); err == nil {
		parseCron(data, "root")
	}

	// User crontabs in /var/spool/cron
	if entries, err := l.OSReadDir("/var/spool/cron"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join("/var/spool/cron", entry.Name())
			if data, err := l.OSReadFile(path); err == nil {
				parseCron(data, entry.Name())
			}
		}
	}

	// System cron directories
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"} {
		if entries, err := l.OSReadDir(dir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					tasks = append(tasks, models.ScheduledTask{
						Name:    entry.Name(),
						Command: filepath.Join(dir, entry.Name()),
						Source:  "cron_dir",
						Enabled: true,
					})
				}
			}
		}
	}

	// Systemd timers from filesystem
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		if entries, err := l.OSReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".timer") {
					continue
				}
				tasks = append(tasks, models.ScheduledTask{
					Name:    strings.TrimSuffix(entry.Name(), ".timer"),
					Source:  "systemd_timer",
					Enabled: true,
				})
			}
		}
	}

	// Live-only user crontab command fallback
	if l.IsLive() {
		if output, err := l.ExecCommand("crontab", "-l").Output(); err == nil {
			parseCron(output, l.OSGetenv("USER"))
		}
	}

	return tasks
}

// CollectActiveConnections collects active network connections
func (l *Linux) CollectActiveConnections(errors *[]string) []models.NetworkConnection {
	if !l.IsLive() {
		return collectProcNetConnections(l)
	}
	return l.CollectNetstatConnections("linux", errors)
}

func collectProcNetConnections(collector SystemPrimitives) []models.NetworkConnection {
	connections := make([]models.NetworkConnection, 0)
	stateMap := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}

	parseFile := func(path, protocol string, ipv6 bool) {
		data, err := collector.OSReadFile(path)
		if err != nil {
			return
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Scan() // header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			localAddr, localPort := parseProcNetAddress(fields[1], ipv6)
			remoteAddr, remotePort := parseProcNetAddress(fields[2], ipv6)
			state := fields[3]
			stateName, ok := stateMap[state]
			if !ok {
				stateName = state
			}
			connections = append(connections, models.NetworkConnection{
				Protocol:      protocol,
				LocalAddress:  localAddr,
				LocalPort:     localPort,
				RemoteAddress: remoteAddr,
				RemotePort:    remotePort,
				State:         stateName,
			})
		}
	}

	parseFile("/proc/net/tcp", "TCP", false)
	parseFile("/proc/net/tcp6", "TCP", true)
	parseFile("/proc/net/udp", "UDP", false)
	parseFile("/proc/net/udp6", "UDP", true)
	connections = append(connections, collectProcNetUnix(collector)...)

	return connections
}

func collectProcNetUnix(collector SystemPrimitives) []models.NetworkConnection {
	connections := make([]models.NetworkConnection, 0)
	data, err := collector.OSReadFile("/proc/net/unix")
	if err != nil {
		return connections
	}
	// Header: Num RefCount Protocol Flags Type St Inode Path
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 {
			continue
		}
		path := ""
		if len(fields) >= 8 {
			path = fields[7]
		}
		connections = append(connections, models.NetworkConnection{
			Protocol:      "UNIX",
			LocalAddress:  path,
			RemoteAddress: "",
			State:         fields[5],
		})
		if len(connections) >= 500 {
			break
		}
	}
	return connections
}

func parseProcNetAddress(value string, ipv6 bool) (string, int) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0
	}

	portHex := parts[1]
	port, _ := strconv.ParseInt(portHex, 16, 64)

	addrHex := parts[0]
	if !ipv6 {
		return parseHexIPv4(addrHex), int(port)
	}

	return parseHexIPv6(addrHex), int(port)
}

func parseHexIPv4(value string) string {
	if len(value) != 8 {
		return ""
	}
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b, err := strconv.ParseUint(value[i*2:(i+1)*2], 16, 8)
		if err != nil {
			return ""
		}
		bytes[i] = byte(b)
	}
	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]).String()
}

func parseHexIPv6(value string) string {
	if len(value) != 32 {
		return ""
	}
	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		b, err := strconv.ParseUint(value[i*2:(i+1)*2], 16, 8)
		if err != nil {
			return ""
		}
		bytes[i] = byte(b)
	}
	for i := 0; i < 16; i += 4 {
		bytes[i], bytes[i+1], bytes[i+2], bytes[i+3] = bytes[i+3], bytes[i+2], bytes[i+1], bytes[i]
	}
	return net.IP(bytes).String()
}

// CollectHostsFile collects the hosts file
func (l *Linux) CollectHostsFile(errors *[]string) *models.ForensicFile {
	return l.CollectHostsFileCommon("/etc/hosts", errors)
}

// CollectSSHKeys collects SSH key information
func (l *Linux) CollectSSHKeys(_ *[]string) []models.SSHKeyInfo {
	return l.CollectSSHKeysCommon()
}

// CollectInstalledSoftware collects installed software information
func (l *Linux) CollectInstalledSoftware(_ *[]string) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)

	if data, err := l.OSReadFile("/var/lib/dpkg/status"); err == nil {
		var name, version string
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			switch {
			case strings.HasPrefix(line, "Package:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
			case strings.HasPrefix(line, "Version:"):
				version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			case line == "" && name != "":
				software = append(software, models.SoftwareInfo{
					Name:    name,
					Version: version,
					Source:  "dpkg",
				})
				name, version = "", ""
			}
		}
		if len(software) > 0 {
			return software
		}
	}

	if pacman := collectPacmanPackages(l); len(pacman) > 0 {
		return pacman
	}

	if rpm := collectRpmPackages(l); len(rpm) > 0 {
		return rpm
	}

	if !l.IsLive() {
		return software
	}

	packageManagers := []struct {
		cmd    string
		args   []string
		source string
	}{
		{"dpkg", []string{"-l"}, "dpkg"},
		{"rpm", []string{"-qa"}, "rpm"},
		{"pacman", []string{"-Q"}, "pacman"},
	}

	for _, pm := range packageManagers {
		//nolint:gosec // G204: pm.cmd and pm.args are from trusted package manager list
		if output, err := l.ExecCommand(pm.cmd, pm.args...).Output(); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				if fields := strings.Fields(scanner.Text()); len(fields) >= 2 {
					sw := models.SoftwareInfo{
						Name:    fields[0],
						Version: fields[1],
						Source:  pm.source,
					}
					if !strings.HasPrefix(sw.Name, "ii") && !strings.HasPrefix(sw.Name, "Desired") {
						software = append(software, sw)
					}
				}
			}
			if len(software) > 0 {
				break
			}
		}
	}

	return software
}

// CollectEnvironmentVariables collects environment variables
func (l *Linux) CollectEnvironmentVariables(_ *[]string) map[string]string {
	return l.CollectEnvironmentVariablesCommon()
}

// CollectRecentDownloads collects recently downloaded files
func (l *Linux) CollectRecentDownloads(_ *[]string) []models.RecentFileEntry {
	return l.CollectDownloadsCommon(nil)
}

// CollectUSBHistory collects USB device connection history
func (l *Linux) CollectUSBHistory(_ *[]string) []models.USBDevice {
	devices := make([]models.USBDevice, 0)
	if !l.IsLive() {
		return devices
	}

	if output, err := l.ExecCommand("dmesg").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "USB") && (strings.Contains(line, "New USB device") || strings.Contains(line, "Product:")) {
				devices = append(devices, models.USBDevice{
					Description: line,
					DeviceID:    "dmesg_entry",
				})
			}
		}
	}

	return devices
}

// CollectPrefetchFiles collects Windows prefetch information (not applicable for Linux)
func (l *Linux) CollectPrefetchFiles(_ *[]string) []models.PrefetchInfo {
	return make([]models.PrefetchInfo, 0)
}

// CollectRecycleBin collects recycle bin contents
func (l *Linux) CollectRecycleBin(_ *[]string) []models.DeletedFile {
	deletedFiles := make([]models.DeletedFile, 0)
	homeDirs, err := l.OSUserHomeDirs()
	if err != nil {
		return deletedFiles
	}

	for _, homeDir := range homeDirs {
		trashPath := filepath.Join(homeDir, ".local", "share", "Trash", "files")
		if entries, err := l.OSReadDir(trashPath); err == nil {
			for _, entry := range entries {
				if info, err := entry.Info(); err == nil {
					deletedFiles = append(deletedFiles, models.DeletedFile{
						DeletedPath:  filepath.Join(trashPath, entry.Name()),
						FileName:     entry.Name(),
						Size:         info.Size(),
						DeletedTime:  info.ModTime().Unix(),
						OriginalPath: "unknown",
					})
				}
			}
		}
	}

	return deletedFiles
}

// CollectClipboard collects current clipboard content
func (l *Linux) CollectClipboard(errors *[]string) string {
	if !l.IsLive() {
		return ""
	}
	cmd := l.ExecCommand("xclip", "-selection", "clipboard", "-o")
	if _, err := l.ExecCommand("which", "xclip").Output(); err != nil {
		cmd = l.ExecCommand("xsel", "--clipboard", "--output")
	}

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

// CollectFilesystemTree collects filesystem tree for Linux
func (l *Linux) CollectFilesystemTree() models.FilesystemTree {
	if l.IsLive() {
		return l.collectFilesystemTreeLive()
	}
	return l.collectFilesystemTreeImage()
}

func (l *Linux) collectFilesystemTreeLive() models.FilesystemTree {
	cmd := l.ExecCommand("find", "/", "-xdev", "-printf", "%p|%y|%s|%u|%g|%m|%T@\n")
	output, err := cmd.Output()
	if err != nil {
		return models.FilesystemTree{Nodes: l.collectTreeWithTreeCommand()}
	}
	return models.FilesystemTree{Nodes: parseLinuxFindOutput(output)}
}

func parseLinuxFindOutput(output []byte) []models.TreeNode {
	nodes := make([]models.TreeNode, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 7)
		if len(parts) < 7 {
			continue
		}
		pathStr := parts[0]
		fileType := mapFindType(parts[1])
		size := parseInt64(parts[2])
		owner := parts[3]
		group := parts[4]
		perm := parts[5]
		mtime := parseFloatTime(parts[6])
		nodes = append(nodes, models.TreeNode{
			Path:         pathStr,
			Name:         filepath.Base(pathStr),
			Parent:       parentPath(pathStr),
			Type:         fileType,
			Size:         size,
			Owner:        owner,
			Group:        group,
			Permissions:  perm,
			ModifiedTime: mtime,
		})
	}
	return nodes
}

func mapFindType(t string) string {
	switch t {
	case "d":
		return "directory"
	case "l":
		return "symlink"
	default:
		return "file"
	}
}
