// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"path/filepath"
	"strings"

	"howett.net/plist"

	"github.com/ilexum-group/tracium/pkg/models"
)

type launchdPlist struct {
	Label            string   `plist:"Label"`
	Program          string   `plist:"Program"`
	ProgramArguments []string `plist:"ProgramArguments"`
	RunAtLoad        bool     `plist:"RunAtLoad"`
	KeepAlive        any      `plist:"KeepAlive"`
	UserName         string   `plist:"UserName"`
}

func parseLaunchdPlist(collector SystemPrimitives, plistPath, dir string) *models.ScheduledTask {
	data, err := collector.OSReadFile(plistPath)
	if err != nil || len(data) == 0 {
		return nil
	}

	var parsed launchdPlist
	if _, err := plist.Unmarshal(data, &parsed); err != nil {
		return nil
	}

	name := parsed.Label
	if name == "" {
		name = filepath.Base(plistPath)
	}

	command := strings.TrimSpace(parsed.Program)
	if command == "" && len(parsed.ProgramArguments) > 0 {
		command = strings.Join(parsed.ProgramArguments, " ")
	}
	if command == "" {
		command = plistPath
	}

	user := parsed.UserName
	if user == "" {
		switch {
		case strings.Contains(dir, "LaunchDaemons"):
			user = "root"
		case strings.Contains(dir, "LaunchAgents"):
			user = "user"
		default:
			user = "unknown"
		}
	}

	descParts := make([]string, 0)
	if parsed.RunAtLoad {
		descParts = append(descParts, "RunAtLoad")
	}
	if parsed.KeepAlive != nil {
		descParts = append(descParts, "KeepAlive")
	}
	description := strings.Join(descParts, ", ")

	return &models.ScheduledTask{
		Name:        name,
		Command:     command,
		User:        user,
		Enabled:     true,
		Source:      "launchd_plist",
		Description: description,
	}
}

type darwinUserPlist struct {
	Name string `plist:"name"`
}

func collectDarwinUsersFromPlist(collector SystemPrimitives) []string {
	users := make([]string, 0)
	base := "/var/db/dslocal/nodes/Default/users"
	entries, err := collector.OSReadDir(base)
	if err != nil {
		return users
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}
		path := filepath.Join(base, entry.Name())
		data, err := collector.OSReadFile(path)
		if err != nil {
			continue
		}
		var parsed darwinUserPlist
		if _, err := plist.Unmarshal(data, &parsed); err != nil {
			continue
		}
		name := strings.TrimSpace(parsed.Name)
		if name == "" {
			name = strings.TrimSuffix(entry.Name(), ".plist")
		}
		if name == "root" || strings.HasPrefix(name, "_") {
			continue
		}
		if !seen[name] {
			seen[name] = true
			users = append(users, name)
		}
	}

	return users
}

type receiptPlist struct {
	BundleIdentifier string `plist:"CFBundleIdentifier"`
	BundleVersion    string `plist:"CFBundleVersion"`
	BundleName       string `plist:"CFBundleName"`
}

func collectDarwinReceipts(collector SystemPrimitives) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)
	paths := []string{
		"/private/var/db/receipts",
		"/Library/Receipts",
	}

	for _, base := range paths {
		entries, err := collector.OSReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			path := filepath.Join(base, entry.Name())
			data, err := collector.OSReadFile(path)
			if err != nil {
				continue
			}
			var parsed receiptPlist
			if _, err := plist.Unmarshal(data, &parsed); err != nil {
				continue
			}
			name := parsed.BundleName
			if name == "" {
				name = parsed.BundleIdentifier
			}
			if name == "" {
				name = strings.TrimSuffix(entry.Name(), ".plist")
			}
			software = append(software, models.SoftwareInfo{
				Name:    name,
				Version: parsed.BundleVersion,
				Source:  "receipt",
			})
			if len(software) >= 500 {
				return software
			}
		}
	}

	return software
}

func collectDarwinApplications(collector SystemPrimitives) []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)
	appDirs := []string{"/Applications", "/System/Applications"}
	for _, dir := range appDirs {
		entries, err := collector.OSReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".app" {
				appName := strings.TrimSuffix(entry.Name(), ".app")
				software = append(software, models.SoftwareInfo{
					Name:    appName,
					Version: "unknown",
					Source:  "applications",
				})
			}
		}
	}
	return software
}

type unifiedLogEntry struct {
	Name string
	Path string
}

func collectDarwinUnifiedLogs(collector SystemPrimitives) []models.LogFile {
	logs := make([]models.LogFile, 0)
	paths := []string{
		"/var/db/diagnostics",
		"/var/log",
	}
	for _, base := range paths {
		entries, err := collector.OSReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(base, entry.Name())
			info, err := collector.OSStat(path)
			if err != nil {
				continue
			}
			logs = append(logs, models.LogFile{
				Name:      entry.Name(),
				Path:      path,
				Size:      info.Size(),
				Content:   "",
				Truncated: false,
			})
		}
	}
	return logs
}
