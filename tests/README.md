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

- **logger_test.go**: Logging system tests

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
