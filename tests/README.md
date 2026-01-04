# Tracium - Testing

## Running Tests

### All tests

```bash
make test
```

### Tests with coverage

```bash
go test -cover ./...
```

### Tests with detailed report

```bash
go test -v ./...
```

## Test Structure

Tests are organized in the `tests/` directory and follow Go conventions:

- Test files end with `_test.go`
- Test functions start with `Test`

### Current Tests

- **logger_test.go**: Logging system tests (RFC 5424 format, log capture, metadata)
  - TestRFC5424Logger: Verifies RFC 5424 compliant format
  - TestLoggerWithoutMetadata: Confirms logging works without structured metadata
  - TestLogCapture: Tests in-memory log capture for server transmission

- **collector_test.go**: Data collection tests
  - TestCollectSystemInfo: System information collection
  - TestCollectHardwareInfo: Hardware information collection
  - TestCollectNetworkInfo: Network configuration collection
  - TestCollectSecurityInfo: Security information collection

- **config_test.go**: Configuration tests
  - TestLoadConfigDefaults: Default configuration values
  - TestLoadConfigEnvVars: Environment variable configuration

- **models_test.go**: Data structure tests
  - TestSystemDataJSON: JSON serialization/deserialization

- **sender_test.go**: Data transmission tests
  - TestSendDataSuccess: Successful transmission (HTTP 200)
  - TestSendDataServerError: Server error handling (HTTP 500)
  - TestSendDataInvalidURL: Invalid URL handling

- **diskimaging_test.go**: Forensic disk imaging tests
  - TestCreateDiskImage: Disk image creation with hash
  - TestCreateDiskImageNonExistent: Non-existent disk handling
  - TestVerifyDiskImage: Hash verification for image integrity

## Tests in CI/CD

Tests run automatically on:
- Push to main/master branch
- Pull Request creation

The CI pipeline verifies:
- ✅ Successful execution of all tests
- ✅ Code coverage
- ✅ Building on all platforms

## Adding New Tests

1. Create a `<component>_test.go` file in the corresponding directory
2. Implement `TestFunctionName(t *testing.T)` functions
3. Run `make test` to validate

Example:

```go
package collector

import "testing"

func TestCollector(t *testing.T) {
    // Arrange
    
    // Act
    
    // Assert
}
```
