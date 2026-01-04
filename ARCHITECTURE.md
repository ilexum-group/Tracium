# Tracium Architecture Documentation

## Table of Contents

1. [Data Transmission Model](#data-transmission-model)
2. [Logging System](#logging-system)
3. [Sequence Diagram](#sequence-diagram)
4. [Data Structures](#data-structures)

---

## Data Transmission Model

### Overview

Tracium uses a secure HTTP(S) protocol with Bearer Token authentication to transmit collected forensic data to a central server. The transmission is a single POST request containing all collected data in JSON format.

### Protocol Specifications

| Aspect | Details |
|--------|---------|
| **Protocol** | HTTP/HTTPS |
| **Method** | POST |
| **Content-Type** | application/json |
| **Authentication** | Bearer Token (HTTP Header) |
| **Encryption** | TLS/SSL (HTTPS recommended) |
| **Response Expected** | HTTP 200 OK |

### Request Structure

#### Headers

```http
POST /v1/data HTTP/1.1
Host: api.tracium.com
Content-Type: application/json
Authorization: Bearer <AGENT_TOKEN>
User-Agent: Tracium-Agent/1.0
Content-Length: <payload_size>
```

- **Content-Type**: Always `application/json`
- **Authorization**: Format is `Bearer {token}` where token is configured via `TRACIUM_AGENT_TOKEN`
- **User-Agent**: Identifies the client as Tracium Agent version 1.0

#### Request Body Structure

```json
{
  "timestamp": 1735961234,
  "system": {
    "os": "linux",
    "hostname": "server01",
    "architecture": "amd64",
    "uptime": 3600,
    "users": ["root", "admin"]
  },
  "hardware": {
    "cpu": {
      "model": "Intel Core i7",
      "cores": 8
    },
    "memory": {
      "total": 17179869184,
      "used": 8589934592
    },
    "disk": [
      {
        "path": "/",
        "total": 536870912000,
        "used": 214748364800,
        "filesystem": "ext4"
      }
    ]
  },
  "network": {
    "interfaces": [
      {
        "name": "eth0",
        "ips": ["192.168.1.10"],
        "mac": "00:1a:2b:3c:4d:5e"
      }
    ],
    "listening_ports": [22, 80, 443]
  },
  "security": {
    "processes": [
      {
        "pid": 1,
        "name": "systemd",
        "user": "root",
        "cpu": 0.1,
        "memory": 1048576
      }
    ],
    "services": [
      {
        "name": "sshd",
        "status": "running",
        "description": "OpenSSH server"
      }
    ]
  },
  "disk_images": [
    {
      "disk_path": "/dev/sda",
      "image_path": "/tmp/image_sda_1735961234.img",
      "image_hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
      "image_size": 1099511627776,
      "status": "completed",
      "timestamp": 1735961234,
      "description": "Forensic image of sda created on 2026-01-04T18:47:14Z"
    }
  ],
  "logs": [
    "<24>1 2026-01-04T18:47:14Z server01 Tracium 1234 - - Starting Tracium agent",
    "<24>1 2026-01-04T18:47:14Z server01 Tracium 1234 - - Configuration loaded",
    "<24>1 2026-01-04T18:47:15Z server01 Tracium 1234 - - Data collection completed",
    "<24>1 2026-01-04T18:47:16Z server01 Tracium 1234 - - Data sent successfully"
  ]
}
```

### Field Descriptions

#### Timestamp
- **Type**: `int64` (Unix timestamp)
- **Description**: Moment when data collection started (seconds since epoch)
- **Example**: `1735961234`

#### System Information
- **os**: Operating system (linux, windows, darwin)
- **hostname**: System hostname
- **architecture**: CPU architecture (amd64, arm64, etc.)
- **uptime**: System uptime in seconds
- **users**: List of system users

#### Hardware Information
- **CPU**: Model name and number of cores
- **Memory**: Total and used memory in bytes
- **Disk**: Array of partition information including filesystem type

#### Network Information
- **interfaces**: List of network interfaces with IP addresses and MAC addresses
- **listening_ports**: Array of ports listening for incoming connections

#### Security Information
- **processes**: Running processes with resource usage (CPU%, memory)
- **services**: Active system services with status and description

#### Disk Images (Optional)
- **disk_path**: Path to the source disk (e.g., /dev/sda)
- **image_path**: Path where the forensic image was saved
- **image_hash**: MD5 hash of the image for integrity verification
- **image_size**: Size of the image in bytes
- **status**: Current status (pending, in_progress, completed, failed)

#### Logs
- **Type**: Array of strings
- **Description**: All RFC 5424 formatted logs captured during agent execution
- **Format**: RFC 5424 compliant syslog entries
- **Content**: Informational, warning, error, and debug messages from all agent components
- **timestamp**: When the image was created
- **description**: Human-readable description of the image

### Authentication Flow

```
1. Agent loads configuration
   ├── Read TRACIUM_SERVER_URL from environment
   └── Read TRACIUM_AGENT_TOKEN from environment

2. Agent collects data
   ├── System information
   ├── Hardware information
   ├── Network information
   ├── Security information
   └── Disk images (optional)

3. Agent marshals data to JSON
   └── Validates JSON structure

4. Agent creates HTTP request
   ├── Sets method to POST
   ├── Sets URL to TRACIUM_SERVER_URL
   ├── Sets headers (Content-Type, Authorization, User-Agent)
   └── Attaches JSON payload

5. Agent sends request
   └── Uses standard Go HTTP client with TLS support

6. Agent receives response
   ├── Validates HTTP status code
   └── Logs success or error
```

### Error Handling

#### Network Errors
- **Timeout**: Request exceeds HTTP client timeout
- **Connection Refused**: Server is not reachable
- **TLS Error**: Invalid certificate or security issue

#### HTTP Errors
- **401 Unauthorized**: Invalid or missing authentication token
- **403 Forbidden**: Valid token but insufficient permissions
- **400 Bad Request**: Malformed JSON payload
- **500 Internal Server Error**: Server-side processing error

#### Logging
Each transmission attempt is logged:
```
- Preparing to send data (INFO level)
- HTTP request details (DEBUG level)
- Success or error (INFO/ERROR level)
- Response status code (INFO level)
```

### Configuration

Transmission is configured via environment variables:

```bash
# Server endpoint (required)
export TRACIUM_SERVER_URL="https://api.tracium.com/v1/data"

# Authentication token (required)
export TRACIUM_AGENT_TOKEN="your-secret-token-here"
```

### Payload Size Considerations

- **Typical payload**: 5-50 KB (system metadata only)
- **With disk images**: Can exceed several GB
- **Network bandwidth**: Large disk images may consume significant bandwidth
- **Timeout**: Configure HTTP client timeout appropriately for large transfers

---

## Logging System

### Overview

Tracium implements RFC 5424 compliant syslog logging for forensic-grade audit trails. The logging system provides structured, standardized logging suitable for compliance and forensic analysis.

### RFC 5424 Standard

RFC 5424 is the modern syslog protocol specification that provides:
- Structured data support
- Precise timestamps (with timezone)
- Priority encoding (facility + severity)
- Version information
- Message ID support

### Log Levels and Severity

Tracium uses four log levels mapped to RFC 5424 severities:

| Level | Severity | Priority | Use Case |
|-------|----------|----------|----------|
| **DEBUG** | Debug (7) | User.Debug (15) | Detailed troubleshooting information |
| **INFO** | Informational (6) | User.Info (14) | General operational messages |
| **WARN** | Warning (4) | User.Warning (12) | Warning conditions requiring attention |
| **ERROR** | Error (3) | User.Error (11) | Error conditions requiring action |

### Log Entry Structure

#### Physical Format

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
```

#### Components

| Component | Description | Example |
|-----------|-------------|---------|
| **PRI** | Priority (facility * 8 + severity) | `<14>` (User facility + Info severity) |
| **VERSION** | RFC 5424 version | `1` |
| **TIMESTAMP** | ISO 8601 UTC timestamp | `2026-01-04T18:47:14.123456Z` |
| **HOSTNAME** | System hostname | `server01` |
| **APP-NAME** | Application name | `Tracium` |
| **PROCID** | Process ID | `12345` |
| **MSGID** | Unique message ID | `ID94700` |
| **STRUCTURED-DATA** | Optional metadata | `[meta@1 key="value"]` |
| **MSG** | Log message content | `Data collection completed` |

### Structured Data Format

Structured data uses the SD-ID format to include metadata:

```
[SDID@ENTERPRISE-NUMBER key1="value1" key2="value2"]
```

For Tracium, the SD-ID is `meta@1`:

```
[meta@1 version="1.0.0" server_url="https://api.tracium.com"]
```

### Log Examples

#### INFO Level - Starting Agent
```
<14>1 2026-01-04T18:47:14.123456Z server01 Tracium 12345 ID94700 [meta@1 version="1.0.0"] Starting Tracium agent
```

#### INFO Level - Configuration Loaded
```
<14>1 2026-01-04T18:47:14.234567Z server01 Tracium 12345 ID94701 [meta@1 server_url="https://api.tracium.com"] Configuration loaded
```

#### INFO Level - Data Collection Completed
```
<14>1 2026-01-04T18:47:15.345678Z server01 Tracium 12345 ID94702 [meta@1 data_points="5"] Data collection completed
```

#### DEBUG Level - HTTP Request Details
```
<15>1 2026-01-04T18:47:15.456789Z server01 Tracium 12345 ID94703 [meta@1 method="POST" content_length="45632"] Sending HTTP request
```

#### WARN Level - Server Error
```
<12>1 2026-01-04T18:47:16.567890Z server01 Tracium 12345 ID94704 [meta@1 status_code="500"] Server returned non-OK status
```

#### ERROR Level - Failed Transmission
```
<11>1 2026-01-04T18:47:17.678901Z server01 Tracium 12345 ID94705 [meta@1 error="connection refused"] Failed to send request
```

### Logging Configuration

The logger is initialized automatically at startup:

```go
if err := utils.InitDefaultLogger(); err != nil {
    panic("Failed to initialize logger: " + err.Error())
}
```

The logger automatically detects and includes:
- System hostname (from OS)
- Process ID (from running process)
- Timestamp (current system time in UTC)

### Log Capture for Transmission

All RFC 5424 logs are automatically captured in memory during agent execution and included in the server transmission payload:

```go
// Before sending data to server
data.Logs = utils.GetLogs()

// Now data contains all captured logs
err := sender.SendData(cfg, data)
```

**Benefits:**
- **Complete audit trail**: All agent operations logged and transmitted
- **Server-side analysis**: Logs stored alongside collected data
- **Forensic integrity**: Logs help verify data collection process
- **Troubleshooting**: Helps diagnose issues on central server
- **Thread-safe**: Concurrent log access protected by mutex

### Metadata Fields

Common metadata fields included in logs:

| Field | Description | Example |
|-------|-------------|---------|
| `version` | Agent version | `"1.0.0"` |
| `server_url` | Target server URL | `"https://api.tracium.com/v1/data"` |
| `data_points` | Number of data types collected | `"5"` |
| `method` | HTTP method | `"POST"` |
| `content_length` | Request body size | `"45632"` |
| `status_code` | HTTP response code | `"200"` |
| `error` | Error description | `"connection refused"` |
| `disk` | Disk path being imaged | `"/dev/sda"` |
| `image_hash` | MD5 hash of disk image | `"a1b2c3d4e5..."` |

### Log Output

All logs are written to **stdout** in RFC 5424 format. To redirect logs:

```bash
# Save to file
./tracium > tracium.log 2>&1

# Send to syslog daemon
./tracium | logger -t tracium
```

### Benefits of RFC 5424 Logging

1. **Forensic Compliance**: Meets standards for digital evidence
2. **Structured Data**: Easy parsing by SIEM systems
3. **Standardization**: Compatible with syslog receivers (rsyslog, syslog-ng)
4. **Traceability**: Complete audit trail of agent actions
5. **Metadata Support**: Context information in each log entry
6. **Precision Timestamps**: High-resolution UTC timestamps
7. **Facility/Severity**: Proper severity classification

---

## Sequence Diagram

### Complete Execution Flow

```
Agent Start
    │
    ├─► Initialize Logger
    │   └─► Create RFC 5424 logger instance
    │       └─► Detect hostname, process ID
    │           └─ LOG: "Starting Tracium agent"
    │
    ├─► Load Configuration
    │   ├─► Read TRACIUM_SERVER_URL
    │   ├─► Read TRACIUM_AGENT_TOKEN
    │   └─ LOG: "Configuration loaded"
    │
    ├─► Collect Data
    │   ├─► Collect System Information
    │   │   ├─► OS, hostname, architecture
    │   │   ├─► Uptime, users
    │   │   └─ LOG: "System info collected"
    │   │
    │   ├─► Collect Hardware Information
    │   │   ├─► CPU details (cores)
    │   │   ├─► Memory (total, used)
    │   │   ├─► Disk partitions
    │   │   └─ LOG: "Hardware info collected"
    │   │
    │   ├─► Collect Network Information
    │   │   ├─► Network interfaces
    │   │   ├─► IP addresses
    │   │   ├─► MAC addresses
    │   │   ├─► Listening ports
    │   │   └─ LOG: "Network info collected"
    │   │
    │   ├─► Collect Security Information
    │   │   ├─► Running processes
    │   │   ├─► System services
    │   │   └─ LOG: "Security info collected"
    │   │
    │   └─ LOG: "Data collection completed"
    │
    ├─► Check Disk Imaging Configuration
    │   │
    │   ├─► IF TRACIUM_ENABLE_DISK_IMAGING == "true"
    │   │   │
    │   │   ├─► Create Disk Image
    │   │   │   ├─► Get disk path (TRACIUM_DISK_PATH)
    │   │   │   ├─► Validate disk accessibility
    │   │   │   ├─► Create output directory
    │   │   │   ├─► Read disk content
    │   │   │   ├─► Calculate MD5 hash
    │   │   │   ├─► Write image file
    │   │   │   ├─ LOG: "Starting disk imaging"
    │   │   │   └─ LOG: "Disk image created successfully"
    │   │   │
    │   │   └─► Add to DiskImages array
    │   │
    │   └─► ELSE
    │       └─ Skip disk imaging
    │
    ├─► Prepare Transmission
    │   ├─► Marshal SystemData to JSON
    │   ├─ LOG: "Preparing to send data to server"
    │   │
    │   ├─► Collect All Logs
    │   │   ├─► Retrieve RFC 5424 formatted logs from logger
    │   │   ├─► Add logs array to SystemData payload
    │   │   └─ Logs include: initialization, configuration, collection, disk imaging steps
    │   │
    │   ├─► Create HTTP POST Request
    │   │   ├─► URL: TRACIUM_SERVER_URL
    │   │   ├─► Method: POST
    │   │   ├─► Body: JSON payload (including logs array)
    │   │   ├─► Header: Content-Type: application/json
    │   │   ├─► Header: Authorization: Bearer {token}
    │   │   ├─► Header: User-Agent: Tracium-Agent/1.0
    │   │   └─ LOG: "HTTP request prepared" (DEBUG)
    │   │
    │   └─► Send HTTP Request
    │       │
    │       ├─► Establish HTTPS connection
    │       ├─► Transmit request with logs
    │       └─ LOG: "Sending HTTP request" (DEBUG)
    │
    ├─► Receive Response
    │   │
    │   ├─► Check HTTP Status Code
    │   │   │
    │   │   ├─► IF Status == 200 OK
    │   │   │   ├─ LOG: "Data sent successfully to server"
    │   │   │   └─► Return success
    │   │   │
    │   │   └─► ELSE
    │   │       ├─ LOG: "Server returned non-OK status" (WARN)
    │   │       └─► Return error
    │   │
    │   └─► Close Response
    │       └─ LOG: Error if close fails (ERROR)
    │
    └─► Exit Agent
        └─ LOG: "Data sent successfully" (final status)
```

### Data Flow with Timing

```
Timeline (milliseconds)
|
├─ T=0ms
│  └─ Agent starts
│     └─ LOG [000ms]: Starting Tracium agent
│
├─ T=10ms
│  └─ Logger initialized
│     └─ LOG [010ms]: Configuration loaded
│
├─ T=20ms
│  └─ Configuration loaded
│
├─ T=30ms
│  └─ Data collection begins
│     ├─ T=40ms: System info collected
│     ├─ T=60ms: Hardware info collected
│     ├─ T=80ms: Network info collected
│     └─ T=100ms: Security info collected
│
├─ T=110ms
│  └─ LOG [110ms]: Data collection completed
│
├─ T=120ms
│  └─ (Optional) Disk imaging
│     ├─ If enabled: T=120ms-T=large value (depends on disk size)
│     └─ LOG: Disk image created successfully
│
├─ T=+data_collection_time
│  └─ JSON marshaling
│     └─ LOG [+10ms]: Preparing to send data to server
│
├─ T=+marshaling_time
│  └─ HTTP transmission
│     ├─ Create request [+5ms]
│     ├─ LOG [DEBUG]: Sending HTTP request
│     └─ Send request [+network_latency]
│
├─ T=+transmission_time
│  └─ Receive response
│     ├─ Read status [+5ms]
│     └─ Validate [+5ms]
│
└─ T=+response_time
   └─ LOG: Data sent successfully
      └─ Agent exits
```

### Error Handling Paths

```
Main Flow
├─► Logger Initialization Failed
│   └─► Panic: "Failed to initialize logger"
│
├─► Configuration Load Failed
│   └─► (Continues with defaults, may fail at transmission)
│
├─► Data Collection Failed
│   ├─► Skips that data category
│   └─► LOG: Category collection error
│
├─► Disk Imaging Failed
│   ├─► LOG: "Failed to create disk image"
│   └─► Continues without disk image
│
├─► JSON Marshaling Failed
│   ├─► LOG: "Failed to marshal data"
│   └─► Return error and exit
│
├─► HTTP Request Failed
│   ├─► Network Error
│   │   ├─► LOG: "Failed to send request"
│   │   └─► Return error and exit
│   │
│   └─► HTTP Error Response
│       ├─► LOG: "Server returned non-OK status"
│       └─► Return error and exit
│
└─► Response Processing Failed
    ├─► LOG: "Failed to close response body"
    └─► Return error (but data may have been sent)
```

### Interaction Diagram

```
┌─────────────────┐         ┌──────────────────┐         ┌──────────────┐
│   Tracium       │         │  File System     │         │   Server     │
│    Agent        │         │    (Local)       │         │  (Remote)    │
└────────┬────────┘         └────────┬─────────┘         └──────┬───────┘
         │                           │                          │
         │─── Initialize Logger ────>│                          │
         │                           │                          │
         │─── Load Configuration ───>│                          │
         │                           │                          │
         │─── Collect System Info ──>│                          │
         │<── Return System Data ────│                          │
         │                           │                          │
         │─── Collect Hardware Info >│                          │
         │<── Return Hardware Data ──│                          │
         │                           │                          │
         │─── Collect Network Info ─>│                          │
         │<── Return Network Data ───│                          │
         │                           │                          │
         │─── Collect Security Info >│                          │
         │<── Return Security Data ──│                          │
         │                           │                          │
         │─── Check Disk Imaging ───>│                          │
         │                           │                          │
         │─ Create Disk Image (opt) >│                          │
         │<── Return Image Metadata ─│                          │
         │                           │                          │
         │─── Marshal to JSON ──────>│                          │
         │<── Return JSON Payload ───│                          │
         │                           │                          │
         │──────── POST JSON ─────────────────────────────────>│
         │                           │                          │
         │                           │         Processing...     │
         │                           │                          │
         │<──────── 200 OK ───────────────────────────────────│
         │                           │                          │
         │─── Log Success ──────────>│                          │
         │                           │                          │
```

---

## Data Structures

### SystemData (Top-level)

```go
type SystemData struct {
    Timestamp   int64         // Unix timestamp of collection
    System      SystemInfo    // OS information
    Hardware    HardwareInfo  // CPU, Memory, Disk
    Network     NetworkInfo   // Interfaces, Ports
    Security    SecurityInfo  // Processes, Services
    DiskImages  []DiskImage   // Forensic disk images
}
```

### All Models

See [internal/models/models.go](internal/models/models.go) for complete definitions.

---

## Summary

This architecture documentation provides:

1. **Data Transmission Model**: Complete specification of how data is sent to the server, including request/response format, authentication, and error handling

2. **Logging System**: RFC 5424 compliant structured logging with multiple severity levels, metadata support, and forensic-grade audit trails

3. **Sequence Diagrams**: Visual representation of execution flow, timing, data flow, error paths, and component interactions

The design ensures secure, auditable, and compliant forensic data collection and transmission.
