// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

// AnalysisMode represents the data acquisition mode.
type AnalysisMode string

const (
	// LiveMode indicates live analysis on the host OS.
	LiveMode AnalysisMode = "live"
	// ImageMode indicates post-mortem analysis from a forensic image.
	ImageMode AnalysisMode = "postmortem"
)

// CollectorOptions configures collector creation.
type CollectorOptions struct {
	ImagePath string
}
