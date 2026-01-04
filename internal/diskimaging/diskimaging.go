// Package diskimaging provides functions to create forensic disk images
package diskimaging

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tracium/internal/models"
	"github.com/tracium/internal/utils"
)

// CreateDiskImage creates a forensic image of the specified disk and returns DiskImage metadata
func CreateDiskImage(diskPath string, outputDir string) (*models.DiskImage, error) {
	utils.LogInfo("Starting disk imaging", map[string]string{"disk": diskPath})

	// Validate input disk exists
	if _, err := os.Stat(diskPath); err != nil {
		utils.LogError("Disk not found", map[string]string{"disk": diskPath, "error": err.Error()})
		return nil, fmt.Errorf("disk not found: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		utils.LogError("Failed to create output directory", map[string]string{"dir": outputDir, "error": err.Error()})
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate image filename
	timestamp := time.Now().Unix()
	diskName := filepath.Base(diskPath)
	imagePath := filepath.Join(outputDir, fmt.Sprintf("image_%s_%d.img", diskName, timestamp))

	// Read disk and create image
	sourceFile, err := os.Open(diskPath)
	if err != nil {
		utils.LogError("Failed to open disk", map[string]string{"disk": diskPath, "error": err.Error()})
		return nil, fmt.Errorf("failed to open disk: %w", err)
	}
	defer func() {
		if err := sourceFile.Close(); err != nil {
			utils.LogError("Failed to close source file", map[string]string{"error": err.Error()})
		}
	}()

	// Get source file info
	_, err = sourceFile.Stat()
	if err != nil {
		utils.LogError("Failed to stat disk", map[string]string{"disk": diskPath, "error": err.Error()})
		return nil, fmt.Errorf("failed to stat disk: %w", err)
	}

	// Create image file
	imageFile, err := os.Create(imagePath)
	if err != nil {
		utils.LogError("Failed to create image file", map[string]string{"path": imagePath, "error": err.Error()})
		return nil, fmt.Errorf("failed to create image file: %w", err)
	}
	defer func() {
		if err := imageFile.Close(); err != nil {
			utils.LogError("Failed to close image file", map[string]string{"error": err.Error()})
		}
	}()

	// Copy disk content to image with hash calculation
	hash := md5.New()
	multiWriter := io.MultiWriter(imageFile, hash)

	copiedBytes, err := io.Copy(multiWriter, sourceFile)
	if err != nil {
		utils.LogError("Failed to copy disk content", map[string]string{"error": err.Error()})
		if err := os.Remove(imagePath); err != nil {
			utils.LogError("Failed to remove incomplete image", map[string]string{"path": imagePath, "error": err.Error()})
		}
		return nil, fmt.Errorf("failed to copy disk content: %w", err)
	}

	imageHash := fmt.Sprintf("%x", hash.Sum(nil))

	utils.LogInfo("Disk imaging completed successfully", map[string]string{
		"disk":       diskPath,
		"image_path": imagePath,
		"size":       fmt.Sprintf("%d", copiedBytes),
		"hash":       imageHash,
	})

	return &models.DiskImage{
		DiskPath:    diskPath,
		ImagePath:   imagePath,
		ImageHash:   imageHash,
		ImageSize:   uint64(copiedBytes),
		Status:      "completed",
		Timestamp:   timestamp,
		Description: fmt.Sprintf("Forensic image of %s created on %s", diskName, time.Now().Format(time.RFC3339)),
	}, nil
}

// GetDiskImages returns a list of all available disks on the system
func GetDiskImages() []string {
	var disks []string

	// Placeholder - in real implementation, enumerate system disks based on OS
	// On Linux: /dev/sda, /dev/sdb, etc.
	// On Windows: \\.\PhysicalDrive0, \\.\PhysicalDrive1, etc.
	// On macOS: /dev/disk0, /dev/disk1, etc.

	return disks
}

// VerifyDiskImage verifies the integrity of a disk image by comparing hashes
func VerifyDiskImage(imagePath string, expectedHash string) bool {
	imageFile, err := os.Open(imagePath)
	if err != nil {
		utils.LogError("Failed to open image file for verification", map[string]string{"path": imagePath, "error": err.Error()})
		return false
	}
	defer func() {
		if err := imageFile.Close(); err != nil {
			utils.LogError("Failed to close image file", map[string]string{"error": err.Error()})
		}
	}()

	hash := md5.New()
	if _, err := io.Copy(hash, imageFile); err != nil {
		utils.LogError("Failed to verify image hash", map[string]string{"path": imagePath, "error": err.Error()})
		return false
	}

	calculatedHash := fmt.Sprintf("%x", hash.Sum(nil))
	isValid := calculatedHash == expectedHash

	if isValid {
		utils.LogInfo("Image verification successful", map[string]string{"path": imagePath})
	} else {
		utils.LogError("Image verification failed", map[string]string{
			"path":            imagePath,
			"expected_hash":   expectedHash,
			"calculated_hash": calculatedHash,
		})
	}

	return isValid
}
