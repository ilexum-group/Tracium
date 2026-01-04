# Forensics Module

The `forensics` package provides comprehensive forensic data collection capabilities for the Tracium agent. It collects evidence from various sources including browsers, file systems, shell histories, and network caches.

## Features

### 1. Browser History Collection
Collects web browsing history from:
- **Chrome**: All platforms (Windows, macOS, Linux)
- **Firefox**: All platforms  
- **Edge**: Windows only

Data includes:
- URL visited
- Page title
- Visit count
- Last visit timestamp
- Whether URL was manually typed

### 2. Cookie Collection
Collects browser cookies (metadata only, values may be encrypted):
- Cookie name and value
- Host domain
- Path
- Expiration time
- Security flags (secure, http_only)
- Creation time

**Note**: Modern browsers encrypt cookie values. Full decryption requires access to OS-level keyrings.

### 3. Recent Files
Collects recently accessed files from:
- **Windows**: Recent Items folder, Jump Lists
- **Linux**: XBEL (recently-used.xbel)
- **macOS**: Recent items

### 4. Command History
Collects shell command execution history from:
- **PowerShell**: ConsoleHost_history.txt (Windows)
- **Bash**: .bash_history (Linux/macOS)
- **Zsh**: .zsh_history (Linux/macOS)
- **Cmd**: Windows command history

### 5. Download History
Collects download records from browser databases:
- File path
- Source URL
- Start and end times
- File size
- Download state (complete, cancelled, interrupted)
- MIME type
- Danger classification

### 6. Network History
Collects network connection evidence:
- **ARP Cache**: IP-to-MAC address mappings
- **DNS Cache**: Hostname resolution history

## Data Structures

### ForensicsData
Main structure containing all forensic artifacts:
```go
type ForensicsData struct {
    BrowserHistory   []BrowserHistoryEntry
    Cookies          []CookieEntry
    RecentFiles      []RecentFileEntry
    CommandHistory   []CommandEntry
    Downloads        []DownloadEntry
    NetworkHistory   NetworkHistoryData
    CollectionErrors []string
}
```

### BrowserHistoryEntry
```go
type BrowserHistoryEntry struct {
    Browser       string // "chrome", "firefox", "edge"
    URL           string
    Title         string
    VisitCount    int
    LastVisitTime int64  // Unix timestamp
    Typed         bool   // User manually typed URL
}
```

### CookieEntry
```go
type CookieEntry struct {
    Browser      string
    Host         string
    Name         string
    Value        string // May be encrypted
    Path         string
    ExpiresTime  int64
    Secure       bool
    HTTPOnly     bool
    CreationTime int64
}
```

### RecentFileEntry
```go
type RecentFileEntry struct {
    FilePath     string
    FileName     string
    AccessedTime int64
    Source       string // "windows_recent", "xbel", etc.
}
```

### CommandEntry
```go
type CommandEntry struct {
    Shell     string // "powershell", "bash", "zsh", "cmd"
    Command   string
    Timestamp int64  // If available
    LineNum   int
}
```

### DownloadEntry
```go
type DownloadEntry struct {
    Browser    string
    FilePath   string
    URL        string
    StartTime  int64
    EndTime    int64
    BytesTotal int64
    State      string // "complete", "cancelled", "interrupted"
    DangerType string
    MimeType   string
}
```

### NetworkHistoryData
```go
type NetworkHistoryData struct {
    ARPCache []ARPEntry
    DNSCache []DNSEntry
}

type ARPEntry struct {
    IPAddress  string
    MACAddress string
    Interface  string
    Type       string // "static", "dynamic"
}

type DNSEntry struct {
    Hostname   string
    IPAddress  []string
    RecordType string // "A", "AAAA", "CNAME"
    TTL        int
}
```

## Usage

### Basic Collection
```go
import "github.com/tracium/internal/forensics"

// Collect all forensic data
data := forensics.CollectForensicsData()

// Access specific collections
for _, entry := range data.BrowserHistory {
    fmt.Printf("%s: %s (%d visits)\n", entry.Browser, entry.URL, entry.VisitCount)
}

// Check for errors
if len(data.CollectionErrors) > 0 {
    fmt.Printf("Encountered %d errors during collection\n", len(data.CollectionErrors))
}
```

### Environment Variables
Forensics collection can be controlled via environment variables:

```bash
# Disable forensics collection (enabled by default)
export TRACIUM_ENABLE_FORENSICS=false

# Run agent with forensics
./tracium
```

## Implementation Details

### Database Access
- Browser databases (SQLite) are **copied to temporary locations** before reading
- This prevents file locking issues when browsers are running
- Temporary files are cleaned up after collection

### Cross-Platform Support
The module automatically detects the operating system and uses appropriate paths:

**Windows**:
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`
- PowerShell: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\`
- Recent: `%APPDATA%\Microsoft\Windows\Recent\`

**Linux**:
- Chrome: `~/.config/google-chrome/Default/`
- Firefox: `~/.mozilla/firefox/*.default*/`
- Bash: `~/.bash_history`
- Recent: `~/.local/share/recently-used.xbel`

**macOS**:
- Chrome: `~/Library/Application Support/Google/Chrome/Default/`
- Firefox: `~/Library/Application Support/Firefox/Profiles/`
- Zsh: `~/.zsh_history`

### Timestamp Conversion
Different browsers use different timestamp formats:
- **Chrome/Edge**: Microseconds since 1601-01-01 (Windows epoch)
- **Firefox**: Microseconds since 1970-01-01 (Unix epoch)

The module automatically converts all timestamps to standard Unix timestamps.

### Error Handling
- Individual collection failures **do not stop** the entire process
- Errors are logged and added to `CollectionErrors` array
- Empty collections are returned on failure (never nil)

## Privacy Considerations

This module collects **extensive forensic data** that may contain sensitive information:
- Browsing history reveals user activity
- Command history may contain credentials or sensitive commands
- Recent files show user document access patterns
- Cookies may contain session tokens (though typically encrypted)

**Recommendations**:
1. Use `TRACIUM_ENABLE_FORENSICS=false` if full forensics are not required
2. Implement data retention policies for collected forensics
3. Ensure secure transmission and storage of forensic data
4. Comply with local privacy laws and regulations
5. Notify users that forensic data is being collected

## Dependencies

- `github.com/mattn/go-sqlite3`: SQLite database driver (requires CGO)
  
**Note**: This package requires CGO to build due to SQLite dependency. Ensure you have a C compiler available:
- **Windows**: Install MinGW-w64 or Visual Studio Build Tools
- **Linux**: Install `gcc` or `build-essential`
- **macOS**: Install Xcode Command Line Tools

## Performance

Forensic collection is **I/O intensive** and may take several seconds to complete:
- Browser history: 1-3 seconds per browser
- Command history: < 1 second
- Recent files: < 1 second
- Network cache: 1-2 seconds
- Downloads: 1-3 seconds per browser

**Estimated total time**: 5-15 seconds depending on data volume and system speed.

## Limitations

1. **Encrypted Data**: Cookie values and saved passwords are encrypted by modern browsers
2. **Locked Databases**: Browsers lock their databases while running (mitigated by copying)
3. **Profile Detection**: May miss non-default browser profiles
4. **Platform Specific**: Some features only work on specific operating systems
5. **Permissions**: Requires read access to user profile directories

## Testing

Run forensics tests:
```bash
go test -v ./tests -run TestForensics
```

**Note**: Tests may produce different results on different systems depending on:
- Installed browsers
- User activity history
- Operating system
- File system permissions

## Future Enhancements

Potential improvements:
- [ ] Decrypt Chrome cookie values using OS keyring
- [ ] Support for Safari (macOS)
- [ ] Support for Opera, Brave, Vivaldi
- [ ] Parse browser cache files
- [ ] Collect browser extensions
- [ ] Extract saved passwords (requires keyring access)
- [ ] Collect browser bookmarks
- [ ] Parse Windows Prefetch files
- [ ] Analyze Windows Registry for additional evidence
- [ ] Support for containerized browsers (Snap, Flatpak)
