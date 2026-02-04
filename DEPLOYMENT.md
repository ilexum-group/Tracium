# Tracium Deployment

## Requirements

- Go 1.25 or higher
- Make utility
- Git

## Building

```bash
# Clone repository
git clone https://github.com/yourusername/tracium.git
cd tracium

# Build for current platform
make build

# Build for all platforms
make build-all
```

## Execution

### Basic Usage
```bash
# Run with required parameters
./build/tracium \
  --server https://api.tracium.com/v1/data \
  --token your-authentication-token \
  --case-id CASE-2026-001

# Run with custom server
./build/tracium \
  --server http://localhost:8080/api/v1/tracium/data \
  --token your-authentication-token \
  --case-id CASE-2026-001
```

### Key Flags
- `--server URL` - Remote server endpoint URL (required)
- `--token TOKEN` - Authentication token for remote server (required)
- `--case-id ID` - Case identifier for correlation (required)

### Platform-Specific Execution

#### Linux
```bash
./build/tracium --server URL --token TOKEN --case-id CASE-2026-001
```

#### Windows
```cmd
build\tracium.exe --server URL --token TOKEN --case-id CASE-2026-001
```

#### macOS
```bash
./build/tracium --server URL --token TOKEN --case-id CASE-2026-001
```

## Cross-Platform Builds

```bash
# Build for all platforms
make build-all

# Build specific platforms
make build-linux
make build-darwin
make build-windows
make build-freebsd
make build-openbsd

# Create release archives
make release
```

## Binary Distribution

Tracium produces a single static binary with zero dependencies:
- No installation required
- No external libraries needed
- Runs directly from command line
- Suitable for incident response USB drives

## System Requirements

### Minimum
- CPU: Single core
- RAM: 512 MB
- Disk: 100 MB free space
- Network: HTTPS connectivity (if transmission enabled)

### Recommended
- CPU: Dual core or higher
- RAM: 2 GB
- Disk: 1 GB free space (more for forensics artifacts)

## Execution Context

### Permissions Required
- **Linux/macOS**: Root/sudo recommended for complete data collection
- **Windows**: Administrator privileges recommended
- **Limited permissions**: Agent runs with reduced capability

### Running as Root/Administrator
```bash
# Linux/macOS
sudo ./build/tracium --server URL --token TOKEN --case-id CASE-2026-001

# Windows (Run as Administrator)
build\tracium.exe --server URL --token TOKEN --case-id CASE-2026-001
```

## Configuration Options

### Server URL
Required parameter. No default value.

Specify with `--server` flag:
```bash
./build/tracium --server http://internal.server:8080/api/v1/tracium/data --token TOKEN --case-id ID
```

### Authentication Token
Required parameter.

```bash
./build/tracium --server URL --token "your-secret-token-here" --case-id ID
```

### Case ID
Required parameter for evidence correlation.

```bash
./build/tracium --server URL --token TOKEN --case-id "INCIDENT-2026-001"
```


## Output and Logging

### Standard Output
All logs are written to stdout in RFC 5424 format:
```bash
# Save logs to file
./build/tracium --server URL --token TOKEN --case-id CASE-2026-001 > tracium_run.log 2>&1

# Send to syslog
./build/tracium --server URL --token TOKEN --case-id CASE-2026-001 | logger -t tracium
```

### Exit Codes
- `0` - Success
- `1` - Error (check logs for details)

## Security Considerations

### TLS/HTTPS
- All transmissions use HTTPS
- Certificate validation enabled by default
- Bearer token authentication

### Data Privacy
- Agent collects system metadata only
- No user credentials captured
- Browser databases collected but not parsed
- Chain of custody for all operations

### Network Requirements
- Outbound HTTPS (port 443) required
- No inbound connections needed
- Firewall rules may need adjustment

## Troubleshooting

### Build Issues
```bash
# Clean and rebuild
make clean
make deps
make build
```

### Runtime Issues
- Check permissions (root/admin)
- Verify network connectivity
- Validate server URL and token
- Review logs for error details

### Common Errors
- **"Configuration error"**: Missing required flags
- **"Failed to send data"**: Network or authentication issue
- **"Permission denied"**: Insufficient privileges

## Production Deployment

### Incident Response Kit
1. Build binaries for all platforms
2. Create USB drive with binaries
3. Include configuration file or script
4. Test on representative systems

### Automated Collection
```bash
#!/bin/bash
# collect.sh - Automated collection script

CASE_ID="$1"
SERVER_URL="https://api.tracium.com/v1/data"
TOKEN="your-token-here"

./tracium \
  --server "$SERVER_URL" \
  --token "$TOKEN" \
  --case-id "$CASE_ID" \
  > "tracium_${CASE_ID}_$(date +%Y%m%d_%H%M%S).log" 2>&1
```

## Version Management

Version is defined in:
- `cmd/tracium/main.go` - Source constant
- `version` file - Build reference

Update both when releasing new version.
