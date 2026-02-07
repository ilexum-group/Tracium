//go:build !linux

// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

func getLinuxDiskUsage(path string) (uint64, uint64, bool) {
	return 0, 0, false
}
