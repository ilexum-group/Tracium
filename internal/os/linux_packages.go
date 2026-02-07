// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ilexum-group/tracium/pkg/models"
)

func collectPacmanPackages(collector SystemPrimitives) []models.SoftwareInfo {
	packages := make([]models.SoftwareInfo, 0)
	base := "/var/lib/pacman/local"
	entries, err := collector.OSReadDir(base)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		descPath := filepath.Join(base, entry.Name(), "desc")
		data, err := collector.OSReadFile(descPath)
		if err != nil {
			continue
		}
		name, version := parsePacmanDesc(data)
		if name == "" {
			continue
		}
		packages = append(packages, models.SoftwareInfo{
			Name:    name,
			Version: version,
			Source:  "pacman",
		})
		if len(packages) >= 500 {
			break
		}
	}

	return packages
}

func parsePacmanDesc(data []byte) (string, string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var name, version string
	var current string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") {
			current = strings.Trim(line, "%")
			continue
		}
		if line == "" {
			continue
		}
		switch current {
		case "NAME":
			name = line
		case "VERSION":
			version = line
		}
	}
	return name, version
}

func collectRpmPackages(collector SystemPrimitives) []models.SoftwareInfo {
	packages := make([]models.SoftwareInfo, 0)

	sqlitePath := "/var/lib/rpm/rpmdb.sqlite"
	data, err := collector.OSReadFile(sqlitePath)
	if err != nil {
		return packages
	}

	tmpFile, err := os.CreateTemp("", "tracium_rpmdb_*.sqlite")
	if err != nil {
		return packages
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return packages
	}
	_ = tmpFile.Close()

	db, err := sql.Open("sqlite", tmpFile.Name())
	if err != nil {
		return packages
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query("SELECT name, version, release, installtime FROM Packages")
	if err != nil {
		return packages
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name, version, release string
		var installTime sql.NullInt64
		if err := rows.Scan(&name, &version, &release, &installTime); err != nil {
			continue
		}
		fullVersion := version
		if release != "" {
			fullVersion = fmt.Sprintf("%s-%s", version, release)
		}
		info := models.SoftwareInfo{
			Name:    name,
			Version: fullVersion,
			Source:  "rpm",
		}
		if installTime.Valid {
			info.InstallDate = time.Unix(installTime.Int64, 0).Format(time.RFC3339)
		}
		packages = append(packages, info)
		if len(packages) >= 500 {
			break
		}
	}

	return packages
}

func parseEpoch(value string) string {
	if value == "" {
		return ""
	}
	if epoch, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(epoch, 0).Format(time.RFC3339)
	}
	return ""
}
