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
)

// SystemPrimitives defines low-level OS operations that can be logged
type SystemPrimitives interface {
	// File operations
	OSReadFile(path string) ([]byte, error)
	OSOpen(path string) (*os.File, error)
	OSStat(path string) (fs.FileInfo, error)
	OSReadDir(path string) ([]fs.DirEntry, error)
	OSCreate(path string) (*os.File, error)
	OSUserHomeDir() (string, error)
	OSGetenv(key string) string

	// User operations
	UserCurrent() (*user.User, error)
	UserLookupID(uid string) (*user.User, error)

	// Command execution
	ExecCommand(name string, args ...string) *exec.Cmd

	// Network operations
	NetInterfaces() ([]net.Interface, error)
}

// OSReadFile wraps os.ReadFile
//
//nolint:gosec // G304: Paths are controlled by forensic collection logic
func (d *Default) OSReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// OSOpen wraps os.Open
//
//nolint:gosec // G304: Paths are controlled by forensic collection logic
func (d *Default) OSOpen(path string) (*os.File, error) {
	return os.Open(path)
}

// OSStat wraps os.Stat
func (d *Default) OSStat(path string) (fs.FileInfo, error) {
	return os.Stat(path)
}

// OSReadDir wraps os.ReadDir
func (d *Default) OSReadDir(path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}

// OSCreate wraps os.Create
//
//nolint:gosec // G304: Paths are controlled by forensic collection logic
func (d *Default) OSCreate(path string) (*os.File, error) {
	return os.Create(path)
}

// OSUserHomeDir wraps os.UserHomeDir
func (d *Default) OSUserHomeDir() (string, error) {
	return os.UserHomeDir()
}

// OSGetenv wraps os.Getenv
func (d *Default) OSGetenv(key string) string {
	return os.Getenv(key)
}

// UserCurrent wraps user.Current
func (d *Default) UserCurrent() (*user.User, error) {
	return user.Current()
}

// UserLookupID wraps user.LookupId
func (d *Default) UserLookupID(uid string) (*user.User, error) {
	return user.LookupId(uid)
}

// ExecCommand wraps exec.Command
func (d *Default) ExecCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// NetInterfaces wraps net.Interfaces
func (d *Default) NetInterfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
