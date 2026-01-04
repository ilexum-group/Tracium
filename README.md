# Tracium - Forensic Analysis and Monitoring Agent

## Overview

Tracium is an advanced analysis and monitoring agent designed for PC and server environments. Developed in Go, this agent specializes in collecting technical evidence, digital forensic analysis, and continuous security monitoring. Running locally on the target system, Tracium collects critical system data and securely transmits it to a centralized server for analysis, storage, and correlation.

## Main Objectives

- **Computer Forensics**: Systematic collection of digital evidence for legal investigations
- **Forensic Analysis**: Real-time system state capture for post-incident analysis
- **Security Monitoring**: Continuous monitoring of processes, services, and system behaviors
- **Technical Evidence Collection**: Complete documentation of system state for audits and compliance

## System Architecture

### Main Components

```
┌─────────────────┐    HTTP(S)    ┌─────────────────┐
│   Target        │─────────────►│   Central       │
│   System        │              │   Server        │
│                 │              │                 │
│ • Tracium Agent │              │ • REST API      │
│ • Collector     │              │ • Database      │
│ • Transmitter   │              │ • Dashboard     │
└─────────────────┘              └─────────────────┘
```

### Project Structure

```
tracium/
├── cmd/tracium/           # Main entry point
│   └── main.go
├── internal/
│   ├── collector/         # Data collection modules
│   │   └── collector.go
│   ├── sender/           # Data transmission module
│   │   └── sender.go
│   ├── config/           # Configuration management
│   │   └── config.go
│   ├── models/           # Data structures
│   │   └── models.go
│   └── utils/            # Auxiliary utilities
│       └── logger.go
├── go.mod
└── README.md
```

## Collected Data

### System Information
- Operating system and version
- Hostname
- Processor architecture
- Uptime
- System users

### Hardware Information
- **CPU**: Model, number of cores, frequency
- **Memory**: Total, used, available
- **Disk**: Partitions, total/used space, filesystem

### Network Information
- Active network interfaces
- Assigned IP addresses
- MAC addresses
- Listening ports (TCP/UDP)

### Security Information
- Running processes (PID, name, user, CPU/memory usage)
- Active system services
- *Future*: Traffic capture, suspicious behavior detection

## Server Communication

### Protocol
- **HTTP/HTTPS** with Bearer Token authentication
- Structured JSON transmission
- Standard security headers

### Configuration
```bash
export TRACIUM_SERVER_URL="https://api.tracium.com/v1/data"
export TRACIUM_AGENT_TOKEN="your-static-token-here"
```

### Data Format
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
  "hardware": {...},
  "network": {...},
  "security": {...}
}
```

## Installation and Configuration

### Prerequisites
- Go 1.25 or higher
- Access to environment variables for configuration
- Make (to use the cross-platform Makefile)
- Git (for version control)

### Dependencies
- [logrus](https://github.com/sirupsen/logrus) - Structured logging
- Go standard libraries for system and network

### Vendoring
This project uses Go modules with vendoring for reproducible builds. Dependencies are included in the `vendor/` directory.

```bash
# Update vendor directory after dependency changes
go mod vendor
```

### Initial Setup
```bash
# Clone the repository
git clone https://github.com/your-org/tracium.git
cd tracium

# Initialize modules and dependencies
go mod tidy
```

### Compilation
```bash
# Build for current platform
make build

# Or build manually
go build -o tracium ./cmd/tracium
```

### Cross-Platform Compilation
Tracium supports cross-platform compilation thanks to Go. Use the included Makefile:

```bash
# Build for all supported platforms
make build-all

# Build for specific platforms
make build-linux      # Linux (amd64, arm64)
make build-darwin     # macOS (amd64, arm64)
make build-windows    # Windows (amd64, arm64)
make build-freebsd    # FreeBSD (amd64)
make build-openbsd    # OpenBSD (amd64)

# Create releases with compressed files
make release
```

Builds are generated in the `build/` directory with descriptive names like `tracium-linux-amd64`, `tracium-windows-amd64.exe`, etc.

### Configuration
1. Set the server URL:
   ```bash
   export TRACIUM_SERVER_URL="https://your-server.com/api/v1/data"
   ```

2. Configure the authentication token:
   ```bash
   export TRACIUM_AGENT_TOKEN="your-secure-static-token"
   ```

### Execution
```bash
# Basic execution
./tracium

# With detailed logging (future)
./tracium -verbose
```

## Security and Privacy Considerations

### Data Security
- **Encryption**: All communication uses HTTPS
- **Authentication**: Static tokens with recommended rotation
- **Integrity**: Checksum verification in transmissions

### Privacy
- Collection limited to necessary technical data
- No capture of personal data without forensic justification
- Compliance with data protection regulations (GDPR, CCPA)

### Best Practices
- Run with minimum necessary privileges
- Rotate tokens regularly
- Monitor transmission logs
- Implement rate limiting on the server

## Use Cases

### 1. Forensic Investigation
- System state capture during incidents
- Digital evidence documentation
- Event timeline analysis

### 2. Continuous Monitoring
- Critical process monitoring
- Configuration change detection
- Proactive security alerts

### 3. Security Audits
- System asset inventory
- Network configuration verification
- Compliance with security standards

### 4. Incident Response
- Rapid evidence collection
- System compromise analysis
- Automated forensic documentation

## Future Enhancements

### Advanced Modules
- **Traffic Capture**: Wireshark/tshark integration
- **Memory Analysis**: Volatility framework integration
- **Malware Detection**: YARA rules engine
- **Log Analysis**: System log parsing and correlation

### Integrations
- **SIEM**: Splunk, ELK Stack, QRadar
- **SOAR**: Response automation
- **Cloud**: Azure Sentinel, AWS GuardDuty
- **Forensic**: Autopsy, EnCase integration

### Additional Features
- **Daemon Mode**: Continuous execution with configurable intervals
- **Compression**: Data transmission optimization
- **Offline Mode**: Local storage when no connectivity
- **Plugin System**: Extensibility through plugins

## Contribution

### Development
1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-functionality`
3. Commit changes: `git commit -am 'Add new functionality'`
4. Push: `git push origin feature/new-functionality`
5. Create Pull Request

### Code Standards
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Use [logrus](https://github.com/sirupsen/logrus) for structured logging
- Include tests for new functionalities
- Document public APIs

## License

This project is under the MIT License. See LICENSE file for details.

## Support

For technical support or inquiries:
- Email: support@tracium.com
- Documentation: https://docs.tracium.com
- Issues: https://github.com/your-org/tracium/issues

---

**Tracium** - Empowering cybersecurity with intelligent forensic analysis.