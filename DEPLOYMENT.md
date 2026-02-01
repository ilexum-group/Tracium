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
# Run with default settings
./build/tracium -case-id CASE-2026-001

# Run with custom server
./build/tracium \
  -server-url http://localhost:8080/api/v1/tracium/data \
  -agent-token your-authentication-token \
  -case-id CASE-2026-001
```

### Key Flags
- `-server-url URL` - Processor endpoint (default: https://api.tracium.com/v1/data)
- `-agent-token TOKEN` - Bearer token for authentication
- `-case-id ID` - Case identifier for correlation
- `-enable-forensics` - Enable forensic artifact collection (default: true)
- `-disk-in-vm VALUE` - Disk attached in VM (true/false)

### Platform-Specific Execution

#### Linux
```bash
./build/tracium -case-id CASE-2026-001
```

#### Windows
```cmd
build\tracium.exe -case-id CASE-2026-001
```

#### macOS
```bash
./build/tracium -case-id CASE-2026-001
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
