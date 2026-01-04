# Tracium - Building and Installation

## Building

### Build for current platform

```bash
make build
```

This will generate the `tracium` executable (or `tracium.exe` on Windows) in the `build/` directory.

### Manual Build

```bash
go build -o tracium ./cmd/tracium
```

## Cross-Platform Building

Tracium supports building for multiple platforms and architectures thanks to Go:

```bash
# Build for all supported platforms
make build-all

# Build for specific platforms
make build-linux      # Linux (amd64, arm64)
make build-darwin     # macOS (amd64, arm64)
make build-windows    # Windows (amd64, arm64)
make build-freebsd    # FreeBSD (amd64)
make build-openbsd    # OpenBSD (amd64)

# Create compressed releases
make release
```

Binaries are generated in the `build/` directory with descriptive names such as:
- `tracium-linux-amd64`
- `tracium-windows-amd64.exe`
- `tracium-darwin-amd64`

## Running

### Prerequisites
- Environment variables configured:
  - `TRACIUM_SERVER_URL` - Central server URL
  - `TRACIUM_AGENT_TOKEN` - Authentication token

### Run the agent

```bash
./build/tracium
```

## Build Validation

```bash
make validate
```

## CI/CD

The project includes automated GitHub Actions pipelines:

### Continuous Integration (CI)
- Runs on push to main/master or Pull Requests
- Validates: tests, build, code format, static analysis, security

### Release Pipeline
- Runs when creating a release on GitHub
- Builds for all supported platforms and architectures
- Automatically uploads binaries to the release

To create a release:
1. Go to the "Releases" tab on GitHub
2. Click "Create a new release"
3. Tag the version (e.g., `v1.0.0`)
4. The pipeline will run automatically
