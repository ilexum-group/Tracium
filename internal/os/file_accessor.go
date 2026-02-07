// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"io/fs"
	"os"
)

// FileAccessor abstracts file access for live and image modes.
type FileAccessor interface {
	ReadFile(path string) ([]byte, error)
	Open(path string) (*os.File, error)
	Stat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
}

type hostFileAccessor struct{}

func newHostFileAccessor() FileAccessor {
	return &hostFileAccessor{}
}

//nolint:gosec // G304: Paths are controlled by forensic collection logic
func (h *hostFileAccessor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

//nolint:gosec // G304: Paths are controlled by forensic collection logic
func (h *hostFileAccessor) Open(path string) (*os.File, error) {
	return os.Open(path)
}

func (h *hostFileAccessor) Stat(path string) (fs.FileInfo, error) {
	return os.Stat(path)
}

func (h *hostFileAccessor) ReadDir(path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}
