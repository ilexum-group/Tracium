// Package sender handles sending collected data to the remote server
package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/tracium/internal/config"
	"github.com/tracium/internal/models"
	"github.com/tracium/internal/utils"
)

const (
	// ChunkSize defines the size of each chunk for disk images (64 MB)
	ChunkSize = 64 * 1024 * 1024
	// MaxPayloadSize defines the maximum JSON payload size before chunking (100 MB)
	MaxPayloadSize = 100 * 1024 * 1024
)

// SendData sends the collected data to the server with intelligent chunking
// Strategy: Send metadata first, then stream disk images separately
func SendData(cfg *config.Config, data models.SystemData) error {
	utils.LogInfo("Preparing to send data to server", map[string]string{"url": cfg.ServerURL})

	// Strategy 1: Check if we have disk images to send separately
	if len(data.DiskImages) > 0 {
		return sendWithDiskImageChunking(cfg, data)
	}

	// Strategy 2: For data without disk images, check payload size
	return sendJSONPayload(cfg, data)
}

// sendJSONPayload sends data as a single JSON payload
func sendJSONPayload(cfg *config.Config, data models.SystemData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		utils.LogError("Failed to marshal data", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	contentLength := len(jsonData)
	utils.LogDebug("Sending JSON payload", map[string]string{
		"content_length": fmt.Sprintf("%d bytes", contentLength),
		"size_mb":        fmt.Sprintf("%.2f MB", float64(contentLength)/1024/1024),
	})

	return sendHTTPRequest(cfg, bytes.NewBuffer(jsonData), contentLength, "application/json")
}

// sendWithDiskImageChunking sends metadata first, then disk images separately
func sendWithDiskImageChunking(cfg *config.Config, data models.SystemData) error {
	// Step 1: Send metadata without disk images first
	metadata := data
	metadata.DiskImages = nil // Remove disk images from first transmission

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		utils.LogError("Failed to marshal metadata", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	utils.LogInfo("Sending metadata payload", map[string]string{
		"disk_images": fmt.Sprintf("%d", len(data.DiskImages)),
		"size_bytes":  fmt.Sprintf("%d", len(metadataJSON)),
	})

	if err := sendHTTPRequest(cfg, bytes.NewBuffer(metadataJSON), len(metadataJSON), "application/json"); err != nil {
		utils.LogError("Failed to send metadata", map[string]string{"error": err.Error()})
		return err
	}

	utils.LogInfo("Metadata sent successfully", map[string]string{})

	// Step 2: Send each disk image separately
	for idx, diskImage := range data.DiskImages {
		utils.LogInfo("Sending disk image chunk", map[string]string{
			"image_number": fmt.Sprintf("%d/%d", idx+1, len(data.DiskImages)),
			"image_path":   diskImage.ImagePath,
			"image_hash":   diskImage.ImageHash,
		})

		if err := sendDiskImageChunked(cfg, diskImage); err != nil {
			utils.LogError("Failed to send disk image", map[string]string{
				"image_path": diskImage.ImagePath,
				"error":      err.Error(),
			})
			return err
		}
	}

	utils.LogInfo("All disk images sent successfully", map[string]string{
		"total_images": fmt.Sprintf("%d", len(data.DiskImages)),
	})

	return nil
}

// sendDiskImageChunked sends a disk image file in chunks
func sendDiskImageChunked(cfg *config.Config, diskImage models.DiskImage) error {
	file, err := os.Open(diskImage.ImagePath)
	if err != nil {
		return fmt.Errorf("failed to open disk image: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			utils.LogError("Failed to close disk image file", map[string]string{"error": err.Error()})
		}
	}()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	fileSize := fileInfo.Size()
	totalChunks := (fileSize + ChunkSize - 1) / ChunkSize

	utils.LogInfo("Starting chunked transfer", map[string]string{
		"file_size":     fmt.Sprintf("%d bytes", fileSize),
		"size_mb":       fmt.Sprintf("%.2f MB", float64(fileSize)/1024/1024),
		"chunk_size_mb": fmt.Sprintf("%.2f MB", float64(ChunkSize)/1024/1024),
		"total_chunks":  fmt.Sprintf("%d", totalChunks),
	})

	chunkBuffer := make([]byte, ChunkSize)
	chunkNum := 0

	for {
		bytesRead, err := file.Read(chunkBuffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		if bytesRead == 0 {
			break
		}

		chunkNum++
		chunkData := chunkBuffer[:bytesRead]

		// Prepare chunk metadata
		chunkPayload := map[string]interface{}{
			"type":         "disk_image_chunk",
			"image_path":   diskImage.ImagePath,
			"image_hash":   diskImage.ImageHash,
			"chunk_num":    chunkNum,
			"total_chunks": totalChunks,
			"chunk_size":   bytesRead,
			"file_size":    fileSize,
			"data":         string(chunkData),
		}

		payloadJSON, err := json.Marshal(chunkPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal chunk: %w", err)
		}

		utils.LogDebug("Sending chunk", map[string]string{
			"chunk":      fmt.Sprintf("%d/%d", chunkNum, totalChunks),
			"size_bytes": fmt.Sprintf("%d", bytesRead),
			"size_mb":    fmt.Sprintf("%.2f", float64(bytesRead)/1024/1024),
			"progress":   fmt.Sprintf("%.1f%%", float64(chunkNum*100)/float64(totalChunks)),
		})

		if err := sendHTTPRequest(cfg, bytes.NewBuffer(payloadJSON), len(payloadJSON), "application/json"); err != nil {
			utils.LogError("Failed to send chunk", map[string]string{
				"chunk": fmt.Sprintf("%d/%d", chunkNum, totalChunks),
				"error": err.Error(),
			})
			return err
		}

		utils.LogInfo("Chunk sent successfully", map[string]string{
			"chunk":    fmt.Sprintf("%d/%d", chunkNum, totalChunks),
			"progress": fmt.Sprintf("%.1f%%", float64(chunkNum*100)/float64(totalChunks)),
		})
	}

	return nil
}

// sendHTTPRequest performs the actual HTTP request with proper headers
func sendHTTPRequest(cfg *config.Config, body io.Reader, contentLength int, contentType string) error {
	req, err := http.NewRequest("POST", cfg.ServerURL, body)
	if err != nil {
		utils.LogError("Failed to create request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("User-Agent", "Tracium-Agent/1.0")
	req.ContentLength = int64(contentLength)

	utils.LogDebug("Sending HTTP request", map[string]string{
		"method":            "POST",
		"content_type":      contentType,
		"content_length":    fmt.Sprintf("%d", contentLength),
		"content_length_mb": fmt.Sprintf("%.2f", float64(contentLength)/1024/1024),
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		utils.LogError("Failed to send request", map[string]string{"error": err.Error()})
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			utils.LogError("Failed to close response body", map[string]string{"error": err.Error()})
		}
	}()

	if resp.StatusCode != http.StatusOK {
		utils.LogWarn("Server returned non-OK status", map[string]string{"status_code": fmt.Sprintf("%d", resp.StatusCode)})
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}
