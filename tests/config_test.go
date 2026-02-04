package tests

import (
	"testing"

	"github.com/ilexum-group/tracium/internal/config"
)

func TestLoadConfigDefaults(t *testing.T) {
	// Test that config is created with empty defaults
	cfg, err := config.LoadFromFlags([]string{})
	if err != nil {
		t.Fatalf("Failed to load config from flags: %v", err)
	}
	if cfg.ServerURL != "" {
		t.Errorf("Expected empty server URL, got %s", cfg.ServerURL)
	}
	if cfg.AgentToken != "" {
		t.Errorf("Expected empty agent token, got %s", cfg.AgentToken)
	}
	if cfg.CaseID != "" {
		t.Errorf("Expected empty case ID, got %s", cfg.CaseID)
	}
}

func TestLoadConfigFlags(t *testing.T) {
	cfg, err := config.LoadFromFlags([]string{
		"--server", "http://localhost:8080",
		"--token", "testtoken",
		"--case-id", "CASE-2026-001",
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
}

func TestValidateConfigMissingFields(t *testing.T) {
	// Test validation with missing fields
	cfg := &config.Config{}

	err := config.ValidateConfig(cfg)
	if err == nil {
		t.Error("Expected validation error for empty config")
	}

	// Test with only server
	cfg.ServerURL = "http://localhost"
	err = config.ValidateConfig(cfg)
	if err == nil {
		t.Error("Expected validation error for missing token")
	}

	// Test with server and token
	cfg.AgentToken = "token"
	err = config.ValidateConfig(cfg)
	if err == nil {
		t.Error("Expected validation error for missing case-id")
	}

	// Test with all fields
	cfg.CaseID = "CASE-001"
	err = config.ValidateConfig(cfg)
	if err != nil {
		t.Errorf("Expected no validation error, got: %v", err)
	}
}
