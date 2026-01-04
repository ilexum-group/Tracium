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
- Consider network bandwidth for transmission of large images
