package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tracium/internal/diskimaging"
)

func TestCreateDiskImage(t *testing.T) {
	// Create a temporary test file to simulate a disk
	tmpDir := t.TempDir()
	testDiskPath := filepath.Join(tmpDir, "test_disk.img")

	// Create test disk file with some content
	testContent := []byte("test disk content for forensic imaging")
	if err := os.WriteFile(testDiskPath, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test disk: %v", err)
	}

	// Test disk image creation
	outputDir := t.TempDir()
	diskImage, err := diskimaging.CreateDiskImage(testDiskPath, outputDir)
	if err != nil {
		t.Errorf("Failed to create disk image: %v", err)
		return
	}

	// Verify image was created
	if _, err := os.Stat(diskImage.ImagePath); err != nil {
		t.Errorf("Image file not created: %v", err)
	}

	// Verify metadata
	if diskImage.ImageSize != uint64(len(testContent)) {
		t.Errorf("Expected image size %d, got %d", len(testContent), diskImage.ImageSize)
	}
	if diskImage.Status != "completed" {
		t.Errorf("Expected status 'completed', got %s", diskImage.Status)
	}
	if diskImage.ImageHash == "" {
		t.Error("Image hash is empty")
	}
}

func TestCreateDiskImageNonExistent(t *testing.T) {
	outputDir := t.TempDir()
	diskImage, err := diskimaging.CreateDiskImage("/nonexistent/disk", outputDir)
	if err == nil {
		t.Error("Expected error for nonexistent disk")
	}
	if diskImage != nil {
		t.Error("Expected nil disk image for nonexistent disk")
	}
}

func TestVerifyDiskImage(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testContent := []byte("test content for verification")
	testImagePath := filepath.Join(tmpDir, "test_image.img")

	if err := os.WriteFile(testImagePath, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	// Create disk image to get correct hash
	diskImagePath := filepath.Join(tmpDir, "source_disk")
	if err := os.WriteFile(diskImagePath, testContent, 0644); err != nil {
		t.Fatalf("Failed to create source disk: %v", err)
	}

	diskImage, err := diskimaging.CreateDiskImage(diskImagePath, tmpDir)
	if err != nil {
		t.Fatalf("Failed to create disk image: %v", err)
	}

	// Verify with correct hash
	if !diskimaging.VerifyDiskImage(diskImage.ImagePath, diskImage.ImageHash) {
		t.Error("Verification failed with correct hash")
	}

	// Verify with incorrect hash
	if diskimaging.VerifyDiskImage(diskImage.ImagePath, "wronghash1234") {
		t.Error("Verification should fail with incorrect hash")
	}
}
