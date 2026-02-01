// Package config provides configuration loading and management for the agent
package config

import (
	"flag"
)

// Config holds the configuration for the agent.
type Config struct {
	ServerURL       string
	AgentToken      string
	CaseID          string
	DiskInVM        string
	EnableForensics bool
}

// Default returns the default configuration values.
func Default() *Config {
	return &Config{
		ServerURL:       "https://api.tracium.com/v1/data",
		AgentToken:      "",
		CaseID:          "",
		DiskInVM:        "false",
		EnableForensics: true,
	}
}

// LoadFromFlags loads configuration from CLI flags.
func LoadFromFlags(args []string) (*Config, error) {
	cfg := Default()
	fs := flag.NewFlagSet("tracium", flag.ContinueOnError)
	fs.StringVar(&cfg.ServerURL, "server-url", cfg.ServerURL, "Processor endpoint URL")
	fs.StringVar(&cfg.AgentToken, "agent-token", cfg.AgentToken, "Bearer token for authentication")
	fs.StringVar(&cfg.CaseID, "case-id", cfg.CaseID, "Case identifier for correlation")
	fs.StringVar(&cfg.DiskInVM, "disk-in-vm", cfg.DiskInVM, "Disk is attached in VM (true/false)")
	fs.BoolVar(&cfg.EnableForensics, "enable-forensics", cfg.EnableForensics, "Enable forensic artifact collection")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return cfg, nil
}
