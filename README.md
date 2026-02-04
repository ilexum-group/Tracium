# Tracium

Forensic evidence collection agent for enterprise incident response and digital investigations.

## What It Does

Tracium collects system information and forensic artifacts from endpoints and transmits them securely to analysis servers. It gathers OS details, hardware configuration, network data, running processes, browser history, command history, recent files, and other forensic evidence across Windows, Linux, macOS, FreeBSD, and OpenBSD.

## Key Features

- **Cross-platform**: Runs on Windows, Linux, macOS, BSD variants
- **Comprehensive collection**: System info, forensic artifacts, timeline data
- **Chain of custody**: RFC 5424 logging, cryptographic hashing (MD5, SHA1, SHA256)
- **Secure transmission**: HTTPS delivery with bearer token authentication
- **Timeline generation**: Automatic correlation of file access, commands, downloads, deletions
- **Zero dependencies**: Single binary, no installation required

## Chain of Custody

Tracium implements forensic-grade chain of custody tracking for all operations:

- **RFC 5424 Logging**: Every action logged with structured, standardized format
- **Cryptographic Hashing**: MD5, SHA1, SHA256 hashes for all collected artifacts
- **Complete Audit Trail**: Tracks agent hostname, user, process ID, and timestamps
- **Operation Logging**: All system calls and file operations recorded
- **Transmission Verification**: Confirms successful delivery to analysis servers
- **Timeline Correlation**: Links events across different artifact sources

All custody chain data is automatically included in the transmitted payload, providing complete traceability from collection to analysis.

## Quick Start

### Prerequisites
- Go 1.25+ and Make utility

### Build and Run
```bash
git clone https://github.com/ilexum-group/tracium.git
cd tracium
make build

# Linux/macOS
./build/tracium --server URL --token TOKEN --case-id CASE-2026-001

# Windows
build\tracium.exe --server URL --token TOKEN --case-id CASE-2026-001
```

## Configuration

All settings via CLI flags:

```
--server URL       API endpoint (required)
--token TOKEN      Authentication token (required)
--case-id ID       Case identifier for correlation (required)
```

## Evidence Collection

### Forensic Artifacts
- Browser history and cookies (Chrome, Firefox, Safari, Edge)
- Shell command history (bash, zsh, PowerShell, cmd)
- Recent files and downloads
- USB device connection history
- Prefetch files (Windows)
- Recycle bin / Trash contents
- Clipboard data
- Scheduled tasks and cron jobs
- SSH keys and known hosts
- Installed software inventory
- System logs (syslog, auth.log, Event Log)
- Active network connections
- Running processes and services

### Chain of Custody
- RFC 5424 structured logging
- Cryptographic hashing (MD5, SHA1, SHA256)
- Complete command audit trail
- Transmission verification
- Timeline correlation across artifacts

### Timeline Events
Automatic extraction of:
- File access, modification, creation, deletion timestamps
- Command execution history
- Download and browser activity
- USB device connections
- Program execution (prefetch)
- Network connections

## Usage Examples

### Basic Collection
```bash
# Linux/macOS
./build/tracium \
    --server http://localhost:8080/api/v1/tracium/data \
    --token your-token \
    --case-id CASE-2026-001

# Windows
build\tracium.exe --server http://localhost:8080/api/v1/tracium/data --token your-token --case-id CASE-2026-001
```

## Building for Multiple Platforms

```bash
make build-all       # All supported platforms
make build-linux     # Linux binaries
make build-darwin    # macOS binaries
make build-windows   # Windows binaries
make build-freebsd   # FreeBSD binaries
make build-openbsd   # OpenBSD binaries
make release         # Compressed release archives
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture and design
- [cmd/tracium/README.md](cmd/tracium/README.md) - Build and installation
- [internal/README.md](internal/README.md) - Internal components
- [tests/README.md](tests/README.md) - Testing guide

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details.

## Support

- Documentation: https://docs.tracium.com
- Issues: https://github.com/ilexum-group/tracium/issues