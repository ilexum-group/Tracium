package config

import (
	"os"
)

// Config holds the configuration for the agent
type Config struct {
	ServerURL  string
	AgentToken string
}

// Load loads the configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerURL:  getEnv("TRACIUM_SERVER_URL", "https://api.tracium.com/v1/data"),
		AgentToken: getEnv("TRACIUM_AGENT_TOKEN", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
