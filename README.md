# Tracium - Forensic Analysis and Monitoring Agent

## What It Does

The Tracium binary collects and sends:

1. **System Information** - OS, hostname, architecture, uptime, users
2. **Hardware Information** - CPU model/cores, memory (total/used), disk partitions
3. **Network Information** - Active interfaces, IP addresses, MAC addresses, listening ports
4. **Security Information** - Running processes, active services
5. **Disk Imaging** - Creates forensic copies of disks and sends them to the remote server

Then sends all collected data and disk images to a remote server via HTTPS.

## Quick Start

```bash
git clone https://github.com/ilexum-group/tracium.git
cd tracium
make build
./build/tracium
```

## Configuration

```bash
export TRACIUM_SERVER_URL="https://api.tracium.com/v1/data"
export TRACIUM_AGENT_TOKEN="your-token"
```

## Documentation

- **[cmd/tracium/README.md](cmd/tracium/README.md)** - Building & running
- **[internal/README.md](internal/README.md)** - Technical details
- **[tests/README.md](tests/README.md)** - Testing
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Data transmission model, logging system, sequence diagrams
- **Reviewers**: Automatically assigned to maintainers

#### GitHub Actions Updates
- **Frequency**: Daily (every day at 09:00 UTC)
- **Scope**: Updates GitHub Actions versions
- **PR Limits**: Maximum 5 open PRs at once
- **Labels**: `github-actions`, `automated`

#### Dependabot PR Process
1. **Automatic Creation**: PRs are created automatically when updates are available
2. **CI Validation**: All PRs pass through the full CI pipeline
3. **Security Checks**: Updates are scanned for security vulnerabilities
4. **Auto-Merge**: Dependency updates are automatically merged if all checks pass
5. **Merge Ready**: PRs are ready to merge once CI passes

#### Auto-Merge Policy
- **Safe Updates**: Patch and minor version updates are auto-merged
- **Major Updates**: Major version updates require manual review
- **Security Updates**: Critical security updates are prioritized and auto-merged
- **Test Coverage**: All updates must pass the complete test suite

To enable Dependabot:
1. Go to repository Settings → Security → Code security and analysis
2. Enable "Dependabot security updates"
3. The `.github/dependabot.yml` configuration will handle version updates

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

## Logging System

Tracium implements RFC 5424 compliant syslog logging for forensic-grade audit trails and structured logging. The logging system provides:

### RFC 5424 Compliance
- **Structured Format**: All log entries follow the RFC 5424 syslog standard
- **Priority Levels**: Proper facility and severity encoding (user-level facility)
- **Timestamp**: ISO 8601 formatted timestamps in UTC
- **Structured Data**: Metadata support with SD-ID format `[meta@1 key="value"]`
- **Dynamic Fields**: Hostname and process ID automatically detected

### Log Levels
- **INFO** (severity 6): General operational messages
- **WARN** (severity 4): Warning conditions
- **ERROR** (severity 3): Error conditions
- **DEBUG** (severity 7): Detailed debugging information

### Sample Log Output
```
<14>1 2026-01-04T18:04:10.537894Z andres-pc Tracium 20968 ID94700 [meta@1 test="true" level="info"] Test info message
<12>1 2026-01-04T18:04:10.537894Z andres-pc Tracium 20968 ID94700 [meta@1 test="true" level="warn"] Test warning message
<11>1 2026-01-04T18:04:10.537894Z andres-pc Tracium 20968 ID94700 [meta@1 test="true" level="error"] Test error message
<15>1 2026-01-04T18:04:10.537894Z andres-pc Tracium 20968 ID94700 [meta@1 level="debug" test="true"] Test debug message
```

### Log Format Explanation
- `<PRI>`: Priority (facility * 8 + severity)
- `VERSION`: RFC 5424 version (always 1)
- `TIMESTAMP`: ISO 8601 UTC timestamp
- `HOSTNAME`: System hostname
- `APP-NAME`: Application name (Tracium)
- `PROCID`: Process ID
- `MSGID`: Unique message identifier
- `[STRUCTURED-DATA]`: Optional metadata in SD-ID format
- `MSG`: Log message content

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

### Additional Features
- **Daemon Mode**: Continuous execution with configurable intervals
- **Compression**: Data transmission optimization
- **Offline Mode**: Local storage when no connectivity
- **Plugin System**: Extensibility through plugins

## Contribution

### Development
1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-functionality`
3. Make changes following the code standards
4. **Run local validation**: `./validate.sh` (Linux/macOS)
4. Run tests locally: `go test ./tests/...`
6. Ensure code builds: `go build ./cmd/tracium`
7. Format code: `gofmt -w .`
8. Commit changes: `git commit -am 'Add new functionality'`
9. Push: `git push origin feature/new-functionality`
10. Create Pull Request

### Pull Request Requirements
All pull requests must pass the CI/CD pipeline checks:
- ✅ **Tests**: All tests must pass
- ✅ **Build**: Code must compile successfully
- ✅ **Formatting**: Code must be properly formatted with `gofmt`
- ✅ **Linting**: Must pass golangci-lint checks (includes security scanning)
- ✅ **Coverage**: Test coverage must be maintained

### Code Standards
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Use RFC 5424 compliant structured logging
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