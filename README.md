# Tracium - Forensic Analysis and Monitoring Agent

## Overview

Tracium is a forensic analysis and monitoring agent designed for system evidence collection and transmission to a centralized server. The agent collects comprehensive system information and securely transmits it via HTTPS with Bearer Token authentication.

## Supported Operating Systems

Tracium is developed in Go and supports cross-platform compilation for the following operating systems:

- Linux (x86_64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (x86_64, ARM64)
- FreeBSD (x86_64)
- OpenBSD (x86_64)

## What It Collects

The agent collects and transmits the following data:

1. System Information: operating system, hostname, architecture, uptime, users
2. Hardware Information: CPU model and cores, memory (total and used), disk partitions
3. Network Information: active interfaces, IP addresses, MAC addresses, listening ports
4. Security Information: running processes with resource usage, active system services
5. Disk Imaging: optional forensic copies of disks with MD5 hash verification
6. Execution Logs: RFC 5424 compliant logs of all agent operations and data collection steps

All collected data, disk images, and execution logs are transmitted to the remote server via HTTPS.

## Quick Start

```bash
git clone https://github.com/ilexum-group/tracium.git
cd tracium
make build
./build/tracium
```

## Configuration

Set the following environment variables before running the agent:

```bash
export TRACIUM_SERVER_URL="https://api.tracium.com/v1/data"
export TRACIUM_AGENT_TOKEN="your-authentication-token"
```

Optional configuration for disk imaging:

```bash
export TRACIUM_ENABLE_DISK_IMAGING="true"
export TRACIUM_DISK_PATH="/dev/sda"
export TRACIUM_IMAGE_OUTPUT_DIR="/tmp/images"
```

## Documentation

- [cmd/tracium/README.md](cmd/tracium/README.md) - Building, installation, and execution instructions
- [internal/README.md](internal/README.md) - Internal components and architecture
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