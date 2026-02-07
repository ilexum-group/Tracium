// Package os provides operating system specific information collection
//
//nolint:revive // Package name 'os' is intentional, in separate namespace 'internal/os'
package os

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/ilexum-group/tracium/pkg/models"
)

type offlineRegistry struct {
	hive    registry.Registry
	cleanup func()
}

func openOfflineRegistry(def *Default, hivePath string) (*offlineRegistry, error) {
	// Always read via file accessor to keep file-first behavior.
	data, err := def.OSReadFile(hivePath)
	if err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "tracium_hive_*.dat")
	if err != nil {
		return nil, err
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, err
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return nil, err
	}

	opener := registry.NewOfflineOpener(tmpFile.Name())
	hive, err := opener.Open()
	if err != nil {
		_ = os.Remove(tmpFile.Name())
		return nil, err
	}

	return &offlineRegistry{
		hive: hive,
		cleanup: func() {
			_ = os.Remove(tmpFile.Name())
		},
	}, nil
}

func (r *offlineRegistry) close() {
	if r == nil {
		return
	}
	_ = r.hive.Close()
	if r.cleanup != nil {
		r.cleanup()
	}
}

func registryGetKey(r registry.Registry, path string) (registry.Key, error) {
	return r.OpenKey("", path)
}

func registrySubkeys(key registry.Key) ([]registry.Key, error) {
	return key.Subkeys()
}

func registryKeyName(key registry.Key) string {
	return key.Name()
}

func registryValueString(key registry.Key, name string) (string, bool) {
	val, err := key.ValueString(name)
	if err != nil {
		return "", false
	}
	return strings.TrimRight(val, "\x00"), true
}

func registryValueDWORD(key registry.Key, name string) (uint32, bool) {
	val, err := key.Value(name)
	if err != nil || val == nil {
		return 0, false
	}
	data, err := val.Data()
	if err == nil && len(data) >= 4 {
		return binary.LittleEndian.Uint32(data[:4]), true
	}
	str, err := val.DataString()
	if err == nil {
		if parsed, err := strconv.ParseUint(str, 10, 32); err == nil {
			return uint32(parsed), true
		}
	}

	return 0, false
}

func windowsHivePath(name string) string {
	return filepath.Join("C:\\Windows\\System32\\config", name)
}

func windowsUserHivePath(homeDir string) string {
	return filepath.Join(homeDir, "NTUSER.DAT")
}

func (w *Windows) collectInstalledSoftwareFromRegistry() []models.SoftwareInfo {
	software := make([]models.SoftwareInfo, 0)

	reg, err := openOfflineRegistry(w.Default, windowsHivePath("SOFTWARE"))
	if err != nil {
		return software
	}
	defer reg.close()

	paths := []string{
		"Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}

	for _, path := range paths {
		key, err := registryGetKey(reg.hive, path)
		if err != nil {
			continue
		}
		subkeys, err := registrySubkeys(key)
		if err != nil {
			continue
		}
		for _, sub := range subkeys {
			name, ok := registryValueString(sub, "DisplayName")
			if !ok || name == "" {
				continue
			}
			version, _ := registryValueString(sub, "DisplayVersion")
			publisher, _ := registryValueString(sub, "Publisher")

			software = append(software, models.SoftwareInfo{
				Name:      name,
				Version:   version,
				Publisher: publisher,
				Source:    "registry",
			})
			if len(software) >= 500 {
				return software
			}
		}
	}

	return software
}

func (w *Windows) collectUsersFromRegistry() []string {
	users := make([]string, 0)

	reg, err := openOfflineRegistry(w.Default, windowsHivePath("SOFTWARE"))
	if err != nil {
		return users
	}
	defer reg.close()

	key, err := registryGetKey(reg.hive, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
	if err != nil {
		return users
	}

	subkeys, err := registrySubkeys(key)
	if err != nil {
		return users
	}

	seen := make(map[string]bool)
	for _, sub := range subkeys {
		profilePath, ok := registryValueString(sub, "ProfileImagePath")
		if !ok || profilePath == "" {
			continue
		}
		name := filepath.Base(profilePath)
		if name == "" || name == "Default" || name == "Default User" || name == "All Users" || name == "Public" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			users = append(users, name)
		}
	}

	return users
}

func (w *Windows) collectServicesFromRegistry() []models.ServiceInfo {
	services := make([]models.ServiceInfo, 0)

	reg, err := openOfflineRegistry(w.Default, windowsHivePath("SYSTEM"))
	if err != nil {
		return services
	}
	defer reg.close()

	controlSet := "ControlSet001"
	if selectKey, err := registryGetKey(reg.hive, "Select"); err == nil {
		if current, ok := registryValueDWORD(selectKey, "Current"); ok {
			controlSet = fmt.Sprintf("ControlSet%03d", current)
		}
	}

	servicesKey := fmt.Sprintf("%s\\Services", controlSet)
	key, err := registryGetKey(reg.hive, servicesKey)
	if err != nil {
		return services
	}
	serviceKeys, err := registrySubkeys(key)
	if err != nil {
		return services
	}

	for _, svc := range serviceKeys {
		name := registryKeyName(svc)
		if name == "" {
			continue
		}
		imagePath, _ := registryValueString(svc, "ImagePath")
		displayName, _ := registryValueString(svc, "DisplayName")
		startType, _ := registryValueDWORD(svc, "Start")
		desc := displayName
		if desc == "" {
			desc = imagePath
		}
		if desc != "" {
			desc = fmt.Sprintf("%s (start=%d)", desc, startType)
		}

		services = append(services, models.ServiceInfo{
			Name:        name,
			Status:      "configured",
			Description: desc,
		})
		if len(services) >= 200 {
			break
		}
	}

	return services
}

func (w *Windows) collectUSBHistoryFromRegistry() []models.USBDevice {
	devices := make([]models.USBDevice, 0)

	reg, err := openOfflineRegistry(w.Default, windowsHivePath("SYSTEM"))
	if err != nil {
		return devices
	}
	defer reg.close()

	controlSet := "ControlSet001"
	if selectKey, err := registryGetKey(reg.hive, "Select"); err == nil {
		if current, ok := registryValueDWORD(selectKey, "Current"); ok {
			controlSet = fmt.Sprintf("ControlSet%03d", current)
		}
	}

	usbPath := fmt.Sprintf("%s\\Enum\\USBSTOR", controlSet)
	key, err := registryGetKey(reg.hive, usbPath)
	if err != nil {
		return devices
	}
	deviceClasses, err := registrySubkeys(key)
	if err != nil {
		return devices
	}

	for _, devClass := range deviceClasses {
		instances, err := registrySubkeys(devClass)
		if err != nil {
			continue
		}
		for _, inst := range instances {
			deviceID := fmt.Sprintf("%s\\%s", registryKeyName(devClass), registryKeyName(inst))
			desc, _ := registryValueString(inst, "FriendlyName")
			if desc == "" {
				desc, _ = registryValueString(inst, "DeviceDesc")
			}
			devices = append(devices, models.USBDevice{
				DeviceID:    deviceID,
				Description: desc,
			})
			if len(devices) >= 200 {
				return devices
			}
		}
	}

	return devices
}
