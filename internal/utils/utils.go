// Package utils provides utility functions for the application
//
//nolint:revive // Package name 'utils' is intentional and commonly used in Go projects
package utils

import (
	"github.com/google/uuid"
)

// GenerateRandomID creates a random identifier string UUID-like
func GenerateRandomID() string {
	return uuid.New().String()
}
