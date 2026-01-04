package main

import (
	"os"
	"testing"

	"github.com/tracium/internal/config"
)

func TestLoadConfigDefaults(t *testing.T) {
	if err := os.Unsetenv("TRACIUM_SERVER_URL"); err != nil {
		t.Logf("Warning: failed to unset TRACIUM_SERVER_URL: %v", err)
	}
	if err := os.Unsetenv("TRACIUM_AGENT_TOKEN"); err != nil {
		t.Logf("Warning: failed to unset TRACIUM_AGENT_TOKEN: %v", err)
	}
	cfg := config.Load()
	if cfg.ServerURL != "https://api.tracium.com/v1/data" {
		t.Errorf("Expected default server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "" {
		t.Errorf("Expected empty agent token, got %s", cfg.AgentToken)
	}
}

func TestLoadConfigEnvVars(t *testing.T) {
	if err := os.Setenv("TRACIUM_SERVER_URL", "http://localhost:8080"); err != nil {
		t.Fatalf("Failed to set TRACIUM_SERVER_URL: %v", err)
	}
	if err := os.Setenv("TRACIUM_AGENT_TOKEN", "testtoken"); err != nil {
		t.Fatalf("Failed to set TRACIUM_AGENT_TOKEN: %v", err)
	}
	cfg := config.Load()
	if cfg.ServerURL != "http://localhost:8080" {
		t.Errorf("Expected env server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "testtoken" {
		t.Errorf("Expected env agent token, got %s", cfg.AgentToken)
	}
}
