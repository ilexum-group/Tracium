package tests

import (
	"testing"

	"github.com/ilexum-group/tracium/internal/collector"
)

func TestCollectSystemInfo(t *testing.T) {
	sys := collector.CollectSystemInfo()
	if sys.OS == "" || sys.Hostname == "" {
		t.Error("SystemInfo should have OS and Hostname")
	}
	if len(sys.Users) == 0 {
		t.Error("SystemInfo should have at least one user")
	}
}

func TestCollectHardwareInfo(t *testing.T) {
	hw := collector.CollectHardwareInfo()
	if hw.CPU.Model == "" {
		t.Error("CPUInfo should have a model name")
	}
	if hw.CPU.Cores <= 0 {
		t.Error("CPUInfo should have at least one core")
	}
	if hw.Memory.Total == 0 {
		t.Error("MemoryInfo should have total memory")
	}
}

func TestCollectNetworkInfo(t *testing.T) {
	net := collector.CollectNetworkInfo()
	if len(net.Interfaces) == 0 {
		t.Error("Should have at least one network interface")
	}
}

func TestCollectSecurityInfo(t *testing.T) {
	sec := collector.CollectSecurityInfo()
	if len(sec.Processes) == 0 {
		t.Error("Should have at least one process running")
	}
}
