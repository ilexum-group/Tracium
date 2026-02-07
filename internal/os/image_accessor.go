// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type imageFileAccessor struct {
	imagePath  string
	offset     int64
	inodeCache map[string]int64
	mu         sync.Mutex
}

func newImageFileAccessor(imagePath string) (*imageFileAccessor, error) {
	offset, err := detectImageOffset(imagePath)
	if err != nil {
		return nil, err
	}

	return &imageFileAccessor{
		imagePath:  imagePath,
		offset:     offset,
		inodeCache: make(map[string]int64),
	}, nil
}

// normalizeImagePath converts Windows-style paths to POSIX paths used by TSK.
func normalizeImagePath(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return filepath.ToSlash(p)
}

func detectImageOffset(imagePath string) (int64, error) {
	fmt.Printf("[image_accessor] detectImageOffset: image=%s\n", imagePath)
	partitions, err := listImagePartitions(imagePath)
	if err != nil || len(partitions) == 0 {
		fmt.Printf("[image_accessor] no partitions: err=%v\n", err)
		return 0, nil
	}
	fmt.Printf("[image_accessor] partitions=%d\n", len(partitions))

	for _, part := range partitions {
		fmt.Printf("[image_accessor] checking partition start=%d desc=%s\n", part.startSector, part.description)
		if detectOSOnPartition(imagePath, part.startSector) {
			fmt.Printf("[image_accessor] OS detected at offset=%d\n", part.startSector)
			return part.startSector, nil
		}
	}

	// Fallback: use first non-zero partition start if no OS markers were found.
	for _, part := range partitions {
		if part.startSector > 0 {
			fmt.Printf("[image_accessor] fallback offset=%d\n", part.startSector)
			return part.startSector, nil
		}
	}

	return 0, nil
}

type imagePartition struct {
	startSector int64
	endSector   int64
	length      int64
	description string
}

func listImagePartitions(imagePath string) ([]imagePartition, error) {
	cmd := exec.Command("mmls", imagePath)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[image_accessor] mmls failed: err=%v\n", err)
		return nil, err
	}

	parts := make([]imagePartition, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	re := regexp.MustCompile(`^\s*\d+\:\s+\d+:\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Slot") || strings.Contains(line, "Meta") || strings.Contains(line, "-------") {
			continue
		}

		if m := re.FindStringSubmatch(line); len(m) == 5 {
			start, err1 := strconv.ParseInt(m[1], 10, 64)
			end, err2 := strconv.ParseInt(m[2], 10, 64)
			length, err3 := strconv.ParseInt(m[3], 10, 64)
			if err1 == nil && err2 == nil && err3 == nil && start > 0 {
				parts = append(parts, imagePartition{
					startSector: start,
					endSector:   end,
					length:      length,
					description: strings.TrimSpace(m[4]),
				})
			}
		}
	}

	if len(parts) == 0 {
		fmt.Printf("[image_accessor] no valid partitions parsed\n")
		return nil, fmt.Errorf("no valid partitions found in mmls output")
	}

	fmt.Printf("[image_accessor] parsed partitions=%d\n", len(parts))
	return parts, nil
}

func detectOSOnPartition(imagePath string, offset int64) bool {
	markers := []string{
		"/Windows/System32/config/SYSTEM",
		"/System/Library/CoreServices/SystemVersion.plist",
		"/etc/os-release",
		"/etc/lsb-release",
		"/etc/freebsd-update.conf",
		"/etc/openbsd-release",
	}

	for _, path := range markers {
		cmd := exec.Command("ifind", "-o", strconv.FormatInt(offset, 10), "-n", path, imagePath)
		output, err := cmd.CombinedOutput()
		outStr := strings.TrimSpace(string(output))
		if err != nil {
			fmt.Printf("[image_accessor] marker not found: %s at offset=%d err=%v out=%q\n", path, offset, err, outStr)
			continue
		}
		fields := strings.Fields(outStr)
		if len(fields) == 0 {
			fmt.Printf("[image_accessor] marker empty output: %s at offset=%d out=%q\n", path, offset, outStr)
			continue
		}
		if _, err := strconv.ParseInt(fields[0], 10, 64); err != nil {
			fmt.Printf("[image_accessor] marker non-numeric output: %s at offset=%d out=%q\n", path, offset, outStr)
			continue
		}
		fmt.Printf("[image_accessor] marker found: %s at offset=%d inode=%s\n", path, offset, fields[0])
		return true
	}

	return false
}

func (i *imageFileAccessor) ReadFile(path string) ([]byte, error) {
	inode, err := i.findInode(path)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("icat", "-o", strconv.FormatInt(i.offset, 10), i.imagePath, strconv.FormatInt(inode, 10))
	return cmd.Output()
}

func (i *imageFileAccessor) Open(path string) (*os.File, error) {
	data, err := i.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "tracium_image_*"+filepath.Ext(path))
	if err != nil {
		return nil, err
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return nil, err
	}

	if _, err := tmpFile.Seek(0, 0); err != nil {
		_ = tmpFile.Close()
		return nil, err
	}

	return tmpFile, nil
}

func (i *imageFileAccessor) Stat(path string) (fs.FileInfo, error) {
	inode, err := i.findInode(path)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("istat", "-o", strconv.FormatInt(i.offset, 10), i.imagePath, strconv.FormatInt(inode, 10))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	name := filepath.Base(normalizeImagePath(path))
	fi := &imageFileInfo{name: name}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "Size:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if size, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					fi.size = size
				}
			}
		case strings.HasPrefix(line, "File Modified:"):
			// Format: File Modified: 2024-01-01 12:34:56 (UTC)
			if parts := strings.SplitN(line, "File Modified:", 2); len(parts) == 2 {
				timeStr := strings.TrimSpace(parts[1])
				if ts, err := time.Parse("2006-01-02 15:04:05 (MST)", timeStr); err == nil {
					fi.modTime = ts
				}
			}
		}
	}

	return fi, nil
}

func (i *imageFileAccessor) ReadDir(path string) ([]fs.DirEntry, error) {
	inode, err := i.findInode(path)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("fls", "-o", strconv.FormatInt(i.offset, 10), i.imagePath, strconv.FormatInt(inode, 10))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	entries := make([]fs.DirEntry, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Example: d/d 11: dir
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if name == "." || name == ".." {
			continue
		}
		isDir := strings.HasPrefix(parts[0], "d/")
		entries = append(entries, &imageDirEntry{name: name, dir: isDir})
	}

	return entries, nil
}

func (i *imageFileAccessor) findInode(path string) (int64, error) {
	normPath := normalizeImagePath(path)

	i.mu.Lock()
	if inode, ok := i.inodeCache[normPath]; ok {
		i.mu.Unlock()
		return inode, nil
	}
	i.mu.Unlock()

	cmd := exec.Command("ifind", "-o", strconv.FormatInt(i.offset, 10), "-n", normPath, i.imagePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ifind failed for %s: %w (out=%q)", normPath, err, strings.TrimSpace(string(output)))
	}

	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) == 0 {
		return 0, fmt.Errorf("inode not found for %s (out=%q)", normPath, strings.TrimSpace(string(output)))
	}

	inode, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid inode for %s: %w", normPath, err)
	}

	i.mu.Lock()
	i.inodeCache[normPath] = inode
	i.mu.Unlock()

	return inode, nil
}

type imageFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (i *imageFileInfo) Name() string       { return i.name }
func (i *imageFileInfo) Size() int64        { return i.size }
func (i *imageFileInfo) Mode() fs.FileMode  { return 0 }
func (i *imageFileInfo) ModTime() time.Time { return i.modTime }
func (i *imageFileInfo) IsDir() bool        { return false }
func (i *imageFileInfo) Sys() interface{}   { return nil }

type imageDirEntry struct {
	name string
	dir  bool
}

func (e *imageDirEntry) Name() string { return e.name }
func (e *imageDirEntry) IsDir() bool  { return e.dir }
func (e *imageDirEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e *imageDirEntry) Info() (fs.FileInfo, error) {
	return &imageFileInfo{name: e.name}, nil
}
