# Tracium - Internal Components

## Structure

```
internal/
├── collector/    # Data collection module
├── sender/      # Data transmission module
├── config/      # Configuration management
├── models/      # Data structures
└── utils/       # Auxiliary utilities
```

## Main Modules

### Collector (collector/collector.go)

Responsible for systematic collection of system data:

**System Information:**
- Operating system and version
- Hostname
- Processor architecture
- Uptime
- System users

**Hardware Information:**
- **CPU**: Model, number of cores, frequency
- **Memory**: Total, used, available
- **Disk**: Partitions, total/used space, filesystem

**Network Information:**
- Active network interfaces
- Assigned IP addresses
- MAC addresses
- Listening ports (TCP/UDP)

**Security Information:**
- Running processes (PID, name, user, CPU/memory)
- Active system services

### Sender (sender/sender.go)

Module responsible for secure data transmission to the central server:

- Bearer Token authentication
- HTTPS transmission
- Security header validation
- Error handling and retries

### Config (config/config.go)

Centralized configuration management:

- Reading environment variables
- Parameter validation
- Destination server configuration
- Authentication configuration

### Models (models/models.go)

Defines data structures:

```go
type Data struct {
    Timestamp int64
    System    SystemInfo
    Hardware  HardwareInfo
    Network   NetworkInfo
    Security  SecurityInfo
}
```

### Utils (utils/logger.go)

Utility functions:

- **Logger**: Logging system for debugging and auditing
- Auxiliary functions for data formatting

## Data Format

Collected data is transmitted in structured JSON format:

```json
{
  "timestamp": 1640995200,
  "system": {
    "os": "linux",
    "hostname": "server01",
    "architecture": "amd64",
    "uptime": 3600,
    "users": ["root", "admin"]
  },
  "hardware": {
    "cpu": {...},
    "memory": {...},
    "disk": {...}
  },
  "network": {
    "interfaces": [...],
    "ports": [...]
  },
  "security": {
    "processes": [...],
    "services": [...]
  }
}
```

## External Dependencies

- **[crewjam/rfc5424](https://github.com/crewjam/rfc5424)**: RFC 5424 syslog message format
- Go standard libraries for system and network access

Dependencies are vendored in the `vendor/` directory for reproducible builds.

## Update Dependencies

```bash
go mod tidy
go mod vendor
```
