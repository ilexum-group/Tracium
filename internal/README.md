# Tracium - Internal Components

## Structure

```
internal/
├── collector/     # Data collection module
├── sender/        # Data transmission module
├── config/        # Configuration management
├── models/        # Data structures
├── forensics/     # Forensic artifacts collection
├── diskimaging/   # Disk imaging module
└── utils/         # Auxiliary utilities
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

**Features:**
- Bearer Token authentication
- HTTPS transmission
- Security header validation
- Error handling

**Intelligent Chunked Transfer:**
- **Metadata First**: Sends system data (metadata, logs) before disk images
- **Automatic Chunking**: Disk images split into 64 MB chunks for large files
- **Memory Efficient**: Only 64 MB loaded at a time (prevents OOM on multi-TB images)
- **Progress Tracking**: Real-time logging of chunk transmission progress
- **Network Safe**: Prevents timeout on large file transfers
- **Resumable**: Failed chunks can be retried independently

**Transmission Strategy:**
1. For data WITHOUT disk images: Send as single JSON payload
2. For data WITH disk images:
   - Request 1: Send metadata (system info, hardware, network, security, logs)
   - Requests 2-N: Send each disk image as individual 64 MB chunks
   - Each chunk includes metadata: chunk number, total chunks, progress

**Example Configuration:**
```go
const (
    ChunkSize      = 64 * 1024 * 1024   // 64 MB per chunk
    MaxPayloadSize = 100 * 1024 * 1024  // Switch to chunking at 100 MB
)
```

### Config (config/config.go)

Centralized configuration management:

- Reading environment variables
- Parameter validation
- Destination server configuration
- Authentication configuration

### Models (models/models.go)

Defines data structures:

```go
type SystemData struct {
    Timestamp  int64
    System     SystemInfo
    Hardware   HardwareInfo
    Network    NetworkInfo
    Security   SecurityInfo
    DiskImages []DiskImage
    Forensics  ForensicsData // Forensic artifacts
    Logs       []string      // RFC 5424 formatted logs
}
```

### Forensics (forensics/forensics.go)

Module for collecting forensic artifacts from the system:

**Browser History:**
- Chrome, Firefox, Edge browsing history
- URLs, titles, visit counts, timestamps
- Typed URL detection

**Cookies:**
- Browser cookie metadata
- Host, name, value (may be encrypted)
- Security flags and expiration

**Recent Files:**
- Windows Recent Items folder
- Linux XBEL (recently-used.xbel)
- macOS recent items

**Command History:**
- PowerShell history (Windows)
- Bash history (Linux/macOS)
- Zsh history (Linux/macOS)
- Command line execution records

**Download History:**
- Browser download records
- File paths, URLs, timestamps
- Download state and file sizes

**Network History:**
- ARP cache (IP-to-MAC mappings)
- DNS cache (hostname resolutions)

See [forensics/README.md](forensics/README.md) for detailed documentation.

### DiskImaging (diskimaging/diskimaging.go)

Module for creating forensic disk images:

**Features:**
- Bit-by-bit disk copying
- MD5 hash verification
- Metadata collection (size, creation time, source path)
- Cross-platform support

See [diskimaging/README.md](diskimaging/README.md) for detailed documentation.

### Utils (utils/logger.go)

Utility functions and RFC 5424 compliant logging:

- **Logger**: RFC 5424 compliant logging system
- **Log Capture**: In-memory log buffer for server transmission
- **Thread-safe operations**: Mutex-protected concurrent access to logs
- Functions: `GetLogs()`, `ClearLogs()` for log retrieval and management

**Log Capture Flow:**
1. Each log message is formatted in RFC 5424 standard
2. Formatted message is stored in memory buffer
3. Before transmission, all logs are retrieved and added to SystemData
4. Logs are sent to server as part of the data payload

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
- **[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)**: SQLite database driver for browser databases (requires CGO)
- Go standard libraries for system and network access

Dependencies are vendored in the `vendor/` directory for reproducible builds.

## Update Dependencies

```bash
go mod tidy
go mod vendor
```

## Configuration

Tracium is configured through environment variables:

```bash
export TRACIUM_SERVER_URL="https://api.tracium.com/v1/data"
export TRACIUM_AGENT_TOKEN="your-static-token-here"
```

### Config Module (config/config.go)

- Reads environment variables
- Validates parameters
- Manages server URL and authentication token

## Server Communication

### Protocol

- **HTTP/HTTPS** with Bearer Token authentication
- Structured JSON transmission
- Standard security headers

### Data Format

```json
{
  "timestamp": 1640995200,
  "system": {...},
  "hardware": {...},
  "network": {...},
  "security": {...}
}
```

### Sender Module (sender/sender.go)

Responsible for secure data transmission:
- Bearer Token authentication
- HTTPS transmission
- Security header validation
- Error handling and retries
