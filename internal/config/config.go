// Package config provides configuration loading and management for the agent
package config

import (
	"flag"
	"fmt"
	"os"
)

// Config holds CLI configuration for the Tracium agent
type Config struct {
	ServerURL  string
	AgentToken string
	CaseID     string
	ImagePath  string
}

const usage = `Tracium - System Information Acquisition Agent
A forensic system information collection tool with chain of custody

Usage:
  tracium [options]

Options:
  -h, --help              Show this help message
  -v, --version           Show version information
  --server URL            Remote server endpoint URL (required)
  --token TOKEN           Authentication token for remote server (required)
  --case-id ID            Case identifier for correlation (required)
	--image PATH            Path to forensic image for post-mortem analysis

Examples:
  # Basic system information collection
  tracium --server https://api.tracium.com/v1/data --token TOKEN --case-id "CASE-2025-001"

  # System information with forensics data
  tracium --server https://api.tracium.com/v1/data --token TOKEN --case-id "CASE-2025-001" --forensics

	# Post-mortem analysis from a forensic image
	tracium --server https://api.tracium.com/v1/data --token TOKEN --case-id "CASE-2025-001" --image "E:\\images\\disk.dd"

Chain of Custody:
  All data is collected in read-only mode without system modifications.
  Every operation is logged with timestamps and included in the custody chain.
  System information is transmitted directly to the server.
  All forensic artifacts are hashed for integrity verification.
`

// ParseFlags parses command-line flags and returns configuration
func ParseFlags() *Config {
	cfg := &Config{}

	fs := flag.NewFlagSet("tracium", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}

	fs.StringVar(&cfg.ServerURL, "server", "", "Remote server endpoint URL")
	fs.StringVar(&cfg.AgentToken, "token", "", "Authentication token for remote server")
	fs.StringVar(&cfg.CaseID, "case-id", "", "Case identifier for correlation")
	fs.StringVar(&cfg.ImagePath, "image", "", "Path to forensic image for post-mortem analysis")

	// Handle help and version
	helpFlag := fs.Bool("help", false, "Show help message")
	versionFlag := fs.Bool("v", false, "Show version")
	fs.Bool("h", false, "Show help message")
	fs.Bool("version", false, "Show version")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *helpFlag {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Printf("Tracium v1.0.0\n")
		os.Exit(0)
	}

	return cfg
}

// LoadFromFlags loads configuration from CLI flags (legacy compatibility)
func LoadFromFlags(args []string) (*Config, error) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Set os.Args for ParseFlags
	os.Args = append([]string{"tracium"}, args...)

	cfg := ParseFlags()
	return cfg, nil
}

// ValidateConfig validates that required configuration fields are set
func ValidateConfig(cfg *Config) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("server URL (--server) is required for data transmission")
	}

	if cfg.AgentToken == "" {
		return fmt.Errorf("authentication token (--token) is required")
	}

	if cfg.CaseID == "" {
		return fmt.Errorf("case ID (--case-id) is required for correlation")
	}

	return nil
}
