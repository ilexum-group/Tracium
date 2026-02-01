# Tracium

## Description

Tracium is a forensic analysis and monitoring agent that collects comprehensive system information and forensic artifacts from endpoints. It operates across multiple platforms and transmits evidence securely to centralized analysis servers.

## Purpose

Tracium acquires system-level forensic evidence including operating system details, hardware configuration, network information, running processes, browser history, command history, recent files, and other forensic artifacts. All collected data is transmitted via secure HTTPS to remote analysis servers for investigation.

## Problem It Solves

Incident response and forensic investigations require rapid collection of system artifacts from potentially compromised endpoints. Tracium provides a portable, cross-platform agent that systematically collects forensic evidence without requiring manual intervention, ensuring consistent data collection and secure transmission to centralized analysis platforms for correlation and investigation.

## Quick Start

### Prerequisites
- Go 1.25 or higher
- Make utility

### Building the Application
```bash
git clone https://github.com/ilexum-group/tracium.git
cd tracium
make build
```

### Running on Linux
After building, run the application with:
```bash
./build/tracium -case-id CASE-2026-001
```

### Running on Windows CMD
After building, run the application with:
```cmd
build\tracium.exe -case-id CASE-2026-001
```

## Configuration (CLI Flags)

All runtime configuration is passed via CLI flags. Environment variables are not used for runtime behavior.

**Flags:**

```
-server-url URL       Processor endpoint (default: https://api.tracium.com/v1/data)
-agent-token TOKEN    Bearer token for authentication
-case-id ID           Case identifier for correlation
-enable-forensics     Enable forensic artifact collection (default: true)
-disk-in-vm VALUE     Disk attached in VM (string: true/false)
```

## Digital Evidence Custody Chain

Tracium implements a comprehensive digital evidence custody chain for system forensics:

### Custody Chain Features

**Standardized Hash Algorithms:**
- MD5 (128-bit) - Legacy compatibility
- SHA1 (160-bit) - Legacy compatibility
- SHA256 (256-bit) - Primary integrity verification
- Hashes calculated for complete system data package

**Comprehensive Logging:**
- RFC 5424 compliant structured logs
- All collection activities logged
- Command executions tracked (if any)
- Error and warning tracking

**Custody Transfer Tracking:**
- Initial system data collection
- Transmission to Processor
- Verification at each step

**Rich Timeline Generation:**
- Recent files accessed
- Command history with timestamps
- USB device connections
- Program executions (prefetch)
- File downloads and deletions
- All formatted for TimeAnalysis

**Forensic Artifacts:**
- Browser history and databases
- Command history (bash, PowerShell, cmd)
- Recent files and downloads
- USB device history
- Prefetch files (Windows)
- Recycle bin entries
- Scheduled tasks
- SSH keys and known hosts
- Installed software

**Processor Integration:**
- SystemData with embedded custody chain
- Automatic timeline extraction from artifacts
- TimeAnalysis correlation across evidence sources

### Usage Example

```go
// Create custody chain for system collection
chain, _ := models.NewCustodyChainEntry(caseID, version)

// Add log entries from logger
for _, logEntry := range logger.GetLogs() {
    chain.AddLogEntry(logEntry)
}

// Finalize with system data
systemJSON, _ := json.Marshal(systemData)
chain.Finalize(systemJSON, artifactCount)

// Generate comprehensive timeline
timeline := models.GenerateTimelineFromTracium(systemData)

// Mark transmission
chain.MarkTransmitted(processorURL, response)
```

### Timeline Events Captured

Tracium generates timeline entries for:
- **Recent Files**: Access timestamps from recent file lists
- **Commands**: Execution timestamps from shell history
- **Downloads**: Download timestamps and file access
- **Deletions**: File deletion timestamps from recycle bin
- **USB Devices**: Connection timestamps for USB history
- **Program Execution**: Last run times from prefetch files
- **Network Activity**: Connection timestamps (if available)

All timeline entries include:
- Precise UTC timestamp
- Event type (created, modified, accessed, deleted, executed)
- Source artifact (file_system, command_history, browser_history, etc.)
- Description and artifact path
- Associated user/process (when available)
- Additional metadata (hash, size, etc.)

**Example Usage:**

### On Linux
```bash
./build/tracium \
    -server-url http://localhost:8080/api/v1/tracium/data \
    -agent-token your-authentication-token \
    -case-id CASE-2026-001
```

### On Windows CMD
```cmd
build\tracium.exe -server-url http://localhost:8080/api/v1/tracium/data -agent-token your-authentication-token -case-id CASE-2026-001
```



Disk imaging and raw disk analysis are now performed exclusively by Bitex. Tracium does not access block devices or disk images directly.

## Integration with Bitex

To perform disk analysis, Tracium invokes Bitex as a CLI tool and consumes its JSON output. Bitex must be installed and available in the system PATH.

### Example Integration

```bash
bitex --disk /path/to/disk.img > analysis.json
# Tracium then reads analysis.json for reporting and correlation
```

Configure Bitex separately for disk-level operations. Tracium is responsible only for orchestration, correlation, and reporting.

Optional configuration for forensics:

```bash
# Disable forensics collection (enabled by default)
./build/tracium -enable-forensics=false
```

## Documentation

- [cmd/tracium/README.md](cmd/tracium/README.md) - Building, installation, and execution instructions
- [internal/README.md](internal/README.md) - Internal components and architecture
- [internal/forensics/README.md](internal/forensics/README.md) - Forensic data collection capabilities
- [tests/README.md](tests/README.md) - Testing and test coverage
- [ARCHITECTURE.md](ARCHITECTURE.md) - Comprehensive technical documentation including data transmission model, logging system, and sequence diagrams

## Requirements

- Go 1.25 or higher
- Make utility for build automation
- Git for version control

## Building for Different Platforms

The Makefile provides targets for cross-platform compilation:

```bash
make build-all       # Build for all supported platforms
make build-linux     # Linux binaries
make build-darwin    # macOS binaries
make build-windows   # Windows binaries
make build-freebsd   # FreeBSD binaries
make build-openbsd   # OpenBSD binaries
make release         # Create compressed release archives
```

## License

Copyright 2026 Tracium Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See the [LICENSE](LICENSE) file for the full license text.

## Support

For technical support or inquiries:
- Documentation: https://docs.tracium.com
- Issues: https://github.com/ilexum-group/tracium/issues

---

Tracium - Forensic analysis and evidence collection for enterprise environments.