package tests

import (
	"testing"

	"github.com/ilexum-group/tracium/internal/config"
)

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := config.LoadFromFlags([]string{})
	if err != nil {
		t.Fatalf("Failed to load config from flags: %v", err)
	}
	if cfg.ServerURL != "https://api.tracium.com/v1/data" {
		t.Errorf("Expected default server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "" {
		t.Errorf("Expected empty agent token, got %s", cfg.AgentToken)
	}
}

func TestLoadConfigFlags(t *testing.T) {
	cfg, err := config.LoadFromFlags([]string{
		"-server-url", "http://localhost:8080",
		"-agent-token", "testtoken",
		"-case-id", "CASE-2026-001",
		"-enable-forensics=false",
	})
	if err != nil {
		t.Fatalf("Failed to load config from flags: %v", err)
	}
	if cfg.ServerURL != "http://localhost:8080" {
		t.Errorf("Expected flag server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "testtoken" {
		t.Errorf("Expected flag agent token, got %s", cfg.AgentToken)
	}
	if cfg.CaseID != "CASE-2026-001" {
		t.Errorf("Expected case ID, got %s", cfg.CaseID)
	}
	if cfg.EnableForensics {
		t.Errorf("Expected enable-forensics=false, got true")
	}
}
