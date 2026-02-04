package tests

import (
	"testing"

	"github.com/ilexum-group/tracium/internal/acquisition"
	"github.com/ilexum-group/tracium/internal/forensics"
	osinfo "github.com/ilexum-group/tracium/internal/os"
	"github.com/ilexum-group/tracium/pkg/models"
)

func TestAcquisitionCollectSystemInfo(t *testing.T) {
	// Create OS collector and custody chain
	collector := osinfo.New()
	custodyChain, err := models.NewCustodyChainEntry("Tracium", "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create custody chain: %v", err)
	}
	forensicsCollector := forensics.New(collector, custodyChain)
	acq := acquisition.New(collector, custodyChain, forensicsCollector)

	// Test system info collection
	sys := acq.CollectSystemInfo()
	if sys.OS == "" || sys.Hostname == "" {
		t.Error("SystemInfo should have OS and Hostname")
	}
	if len(sys.Users) == 0 {
		t.Error("SystemInfo should have at least one user")
	}
	t.Logf("OS: %s, Hostname: %s, Users: %v", sys.OS, sys.Hostname, sys.Users)
}

func TestAcquisitionCollectHardwareInfo(t *testing.T) {
	collector := osinfo.New()
	custodyChain, err := models.NewCustodyChainEntry("Tracium", "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create custody chain: %v", err)
	}
	forensicsCollector := forensics.New(collector, custodyChain)
	acq := acquisition.New(collector, custodyChain, forensicsCollector)

	hw := acq.CollectHardwareInfo()
	if hw.CPU.Model == "" {
		t.Error("CPUInfo should have a model name")
	}
	if hw.CPU.Cores <= 0 {
		t.Error("CPUInfo should have at least one core")
	}
	if hw.Memory.Total == 0 {
		t.Error("MemoryInfo should have total memory")
	}
	t.Logf("CPU: %s (%d cores), Memory: %d bytes", hw.CPU.Model, hw.CPU.Cores, hw.Memory.Total)
}

func TestAcquisitionCollectNetworkInfo(t *testing.T) {
	collector := osinfo.New()
	custodyChain, err := models.NewCustodyChainEntry("Tracium", "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create custody chain: %v", err)
	}
	forensicsCollector := forensics.New(collector, custodyChain)
	acq := acquisition.New(collector, custodyChain, forensicsCollector)

	net := acq.CollectNetworkInfo()
	if len(net.Interfaces) == 0 {
		t.Error("Should have at least one network interface")
	}
	t.Logf("Network interfaces: %d, Listening ports: %d", len(net.Interfaces), len(net.ListeningPorts))
}

func TestAcquisitionCollectSecurityInfo(t *testing.T) {
	collector := osinfo.New()
	custodyChain, err := models.NewCustodyChainEntry("Tracium", "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create custody chain: %v", err)
	}
	forensicsCollector := forensics.New(collector, custodyChain)
	acq := acquisition.New(collector, custodyChain, forensicsCollector)

	sec := acq.CollectSecurityInfo()
	if len(sec.Processes) == 0 {
		t.Error("Should have at least one process running")
	}
	t.Logf("Processes: %d, Services: %d", len(sec.Processes), len(sec.Services))
}

func TestAcquisitionCompleteAcquire(t *testing.T) {
	collector := osinfo.New()
	custodyChain, err := models.NewCustodyChainEntry("Tracium", "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create custody chain: %v", err)
	}
	forensicsCollector := forensics.New(collector, custodyChain)
	acq := acquisition.New(collector, custodyChain, forensicsCollector)

	// Test complete acquisition
	data := acq.Acquire()

	if data.System.OS == "" {
		t.Error("Complete acquisition should include system OS")
	}
	if data.Hardware.CPU.Cores == 0 {
		t.Error("Complete acquisition should include CPU cores")
	}
	if len(data.Network.Interfaces) == 0 {
		t.Error("Complete acquisition should include network interfaces")
	}
	if len(data.Security.Processes) == 0 {
		t.Error("Complete acquisition should include processes")
	}

	t.Logf("Complete acquisition successful")
}
