package main

import (
	"os"
	"testing"

	"github.com/tracium/internal/config"
)

func TestLoadConfigDefaults(t *testing.T) {
	os.Unsetenv("TRACIUM_SERVER_URL")
	os.Unsetenv("TRACIUM_AGENT_TOKEN")
	cfg := config.Load()
	if cfg.ServerURL != "https://api.tracium.com/v1/data" {
		t.Errorf("Expected default server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "" {
		t.Errorf("Expected empty agent token, got %s", cfg.AgentToken)
	}
}

func TestLoadConfigEnvVars(t *testing.T) {
	os.Setenv("TRACIUM_SERVER_URL", "http://localhost:8080")
	os.Setenv("TRACIUM_AGENT_TOKEN", "testtoken")
	cfg := config.Load()
	if cfg.ServerURL != "http://localhost:8080" {
		t.Errorf("Expected env server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "testtoken" {
		t.Errorf("Expected env agent token, got %s", cfg.AgentToken)
	}
}
