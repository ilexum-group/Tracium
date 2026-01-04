# Disk Imaging Module

The disk imaging module provides functionality to create forensic copies of disks and send them to the remote server.

## Features

- **Forensic Disk Imaging**: Creates byte-level copies of disks
- **Hash Verification**: MD5 hash calculation for integrity verification
- **Metadata Collection**: Records image path, size, timestamp, and status
- **Error Handling**: Graceful handling of disk access errors

## Usage

Disk imaging is disabled by default. To enable it, set the environment variable:

```bash
export TRACIUM_ENABLE_DISK_IMAGING=true
```

### Configuration Variables

- `TRACIUM_ENABLE_DISK_IMAGING` - Enable disk imaging (default: false)
- `TRACIUM_DISK_PATH` - Path to disk to image (default: "/")
- `TRACIUM_IMAGE_OUTPUT_DIR` - Directory to store images (default: system temp directory)

### Example

```bash
export TRACIUM_ENABLE_DISK_IMAGING=true
export TRACIUM_DISK_PATH="/dev/sda"
export TRACIUM_IMAGE_OUTPUT_DIR="/mnt/forensics"
./tracium
```

## How It Works

1. **Source Validation**: Verifies the disk path exists and is accessible
2. **Image Creation**: Reads disk content byte-by-byte and writes to image file
3. **Hash Calculation**: Computes MD5 hash during the copy process
4. **Metadata Recording**: Stores image information (path, size, hash, timestamp)
5. **Status Update**: Records completion status
6. **Server Transmission**: Sends image metadata with collected data

## Metadata Recorded

For each disk image, the following metadata is collected:

```json
{
  "disk_path": "/dev/sda",
  "image_path": "/tmp/image_sda_1735961234.img",
  "image_hash": "a1b2c3d4e5f6...",
  "image_size": 1099511627776,
  "status": "completed",
  "timestamp": 1735961234,
  "description": "Forensic image of sda created on 2026-01-04T18:47:14Z"
}
```

## Notes

- Disk imaging requires elevated privileges (root on Linux/macOS, Administrator on Windows)
- Large disks may take considerable time to image
- Ensure sufficient disk space for output images
- Disk images are transmitted to the server using intelligent chunking (see Transmission section below)

## Transmission Strategy

### Chunked Transfer for Large Disk Images

The sender module implements automatic chunking for disk images:

**Features:**
- **Metadata First**: System metadata (system, hardware, network, logs) sent first without disk images
- **Chunked Streaming**: Disk images sent in 64 MB chunks to avoid memory issues
- **Progress Tracking**: Detailed logging of chunk transmission progress
- **Error Recovery**: Failed chunks can be retried without resending metadata

**Chunk Structure:**
```json
{
  "type": "disk_image_chunk",
  "image_path": "/tmp/image_sda_1735961234.img",
  "image_hash": "a1b2c3d4e5f6...",
  "chunk_num": 1,
  "total_chunks": 16,
  "chunk_size": 67108864,
  "file_size": 1099511627776,
  "data": "..."
}
```

**Example Transmission Flow:**
1. Send metadata (5-50 KB) - all collected data except disk images
2. Disk image 1 → 16 chunks of 64 MB each (1 TB total)
3. Disk image 2 → N chunks (if multiple images)
4. Each chunk logged with progress percentage

**Benefits:**
- **Memory Efficient**: Only 64 MB loaded at a time
- **Resume Capable**: Chunks can be retried individually
- **Bandwidth Safe**: Prevents connection timeouts on large transfers
- **Server Friendly**: Allows incremental processing on server side
- **Observable**: Real-time progress logging for monitoring

### Configuration

Chunk size and maximum payload are configurable constants in `sender/sender.go`:

```go
const (
    ChunkSize      = 64 * 1024 * 1024  // 64 MB per chunk
    MaxPayloadSize = 100 * 1024 * 1024 // 100 MB max before chunking
)
```

Adjust these values based on:
- Available network bandwidth
- Server processing capacity
- Memory constraints
- Timeout thresholds
