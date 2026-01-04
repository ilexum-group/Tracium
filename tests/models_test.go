package main

import (
	"encoding/json"
	"testing"

	"github.com/tracium/internal/models"
)

func TestSystemDataJSON(t *testing.T) {
	data := models.SystemData{
		Timestamp: 1234567890,
		System: models.SystemInfo{
			OS:           "linux",
			Hostname:     "testhost",
			Architecture: "amd64",
			Uptime:       1000,
			Users:        []string{"root", "admin"},
		},
		Hardware: models.HardwareInfo{
			CPU:    models.CPUInfo{Model: "Intel", Cores: 4},
			Memory: models.MemoryInfo{Total: 8192, Used: 4096},
			Disk:   []models.DiskInfo{{Path: "/", Total: 100000, Used: 50000, FileSystem: "ext4"}},
		},
		Network: models.NetworkInfo{
			Interfaces:     []models.InterfaceInfo{{Name: "eth0", IPs: []string{"192.168.1.2"}, MAC: "00:11:22:33:44:55"}},
			ListeningPorts: []int{22, 80},
		},
		Security: models.SecurityInfo{
			Processes: []models.ProcessInfo{{PID: 1, Name: "init", User: "root"}},
			Services:  []models.ServiceInfo{{Name: "sshd", Status: "running"}},
		},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal SystemData: %v", err)
	}
	var out models.SystemData
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Failed to unmarshal SystemData: %v", err)
	}
	if out.System.OS != "linux" || out.Hardware.CPU.Model != "Intel" {
		t.Error("Unmarshaled data does not match original")
	}
}
