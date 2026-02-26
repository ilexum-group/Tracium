// Package artifactdetector provides signature-based artifact detection and classification
package artifactdetector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ilexum-group/tracium/pkg/models"
)

// File signatures for artifact detection
var (
	// SQLite header signature
	SQLiteSignature = []byte("SQLite format 3")

	// MBOX email file signature
	MBOXSignature = []byte("From ")

	// PST/OST Outlook file signature
	PSTSignature = []byte("!BDN")

	// JSON signature markers
	JSONStartMarkers = []byte("{[")

	// LevelDB signature
	LevelDBSignature = []byte("LevelDB")

	// MDB signature (Microsoft Access)
	MDBSignature = []byte("Standard Jet DB")
)

// ArtifactType represents the type of detected artifact
type ArtifactType string

const (
	// Browser artifacts
	ArtifactTypeHistory          ArtifactType = "history"
	ArtifactTypeCookies          ArtifactType = "cookies"
	ArtifactTypeDownloads        ArtifactType = "downloads"
	ArtifactTypeBookmarks        ArtifactType = "bookmarks"
	ArtifactTypeCache            ArtifactType = "cache"
	ArtifactTypeFormAutofill     ArtifactType = "form_autofill"
	ArtifactTypeSearchHistory    ArtifactType = "search_history"
	ArtifactTypeChromiumProfile  ArtifactType = "chromium_profile"
	ArtifactTypeChromiumExt      ArtifactType = "chromium_extension"
	ArtifactTypeLoginData        ArtifactType = "login_data"
	ArtifactTypeWebApps          ArtifactType = "web_apps"
	ArtifactTypeExtensions       ArtifactType = "extensions"
	ArtifactTypePreferences      ArtifactType = "preferences"
	ArtifactTypeLocalStorage     ArtifactType = "local_storage"
	ArtifactTypeIndexedDB        ArtifactType = "indexeddb"
	ArtifactTypeServiceWorkers   ArtifactType = "service_workers"

	// Communication artifacts
	ArtifactTypeEmailAccount     ArtifactType = "email_account"
	ArtifactTypeEmailMessage     ArtifactType = "email_message"
	ArtifactTypeGmailDrafts      ArtifactType = "gmail_drafts"
	ArtifactTypeGmailSent        ArtifactType = "gmail_sent"
	ArtifactTypeGmailTrash       ArtifactType = "gmail_trash"
	ArtifactTypeGmailAllMail    ArtifactType = "gmail_all_mail"
	ArtifactTypeEmailDefault     ArtifactType = "email_default"
	ArtifactTypePSTFile         ArtifactType = "pst_file"
	ArtifactTypeOSTFile         ArtifactType = "ost_file"
	ArtifactTypeMBOXFile        ArtifactType = "mbox_file"

	// Messaging artifacts
	ArtifactTypeWhatsAppChat    ArtifactType = "whatsapp_chat"
	ArtifactTypeWhatsAppMedia   ArtifactType = "whatsapp_media"
	ArtifactTypeTelegramChat    ArtifactType = "telegram_chat"
	ArtifactTypeTelegramMedia   ArtifactType = "telegram_media"
	ArtifactTypeTelegramData    ArtifactType = "telegram_data"

	// Collaboration artifacts
	ArtifactTypeSlackMessages   ArtifactType = "slack_messages"
	ArtifactTypeSlackFiles      ArtifactType = "slack_files"
	ArtifactTypeTeamsMessages   ArtifactType = "teams_messages"
	ArtifactTypeTeamsFiles      ArtifactType = "teams_files"
	ArtifactTypeThunderbirdMail ArtifactType = "thunderbird_mail"
	ArtifactTypeThunderbirdProfile ArtifactType = "thunderbird_profile"
)

// AppType represents the detected application
type AppType string

const (
	AppChrome      AppType = "chrome"
	AppEdge       AppType = "edge"
	AppFirefox    AppType = "firefox"
	AppOpera      AppType = "opera"
	AppBrave      AppType = "brave"
	AppOutlook    AppType = "outlook"
	AppThunderbird AppType = "thunderbird"
	AppWhatsApp   AppType = "whatsapp"
	AppTelegram   AppType = "telegram"
	AppSlack      AppType = "slack"
	AppTeams      AppType = "teams"
	AppGmail      AppType = "gmail"
	AppUnknown    AppType = "unknown"
)

// OSType represents the operating system
type OSType string

const (
	OSWindows OSType = "windows"
	OSMac     OSType = "macos"
	OSLinux   OSType = "linux"
	OSiOS     OSType = "ios"
	OSAndroid OSType = "android"
)

// DirectoryResult represents the structured result for a detected directory
type DirectoryResult struct {
	Path     string            `json:"Path"`
	OS       string            `json:"OS"`
	App      string            `json:"App"`
	Profile  string            `json:"Profile"`
	Category string            `json:"Category"`
	Files    []string          `json:"Files"`
	Metadata map[string]interface{} `json:"Metadata,omitempty"`
}

// DirEntry represents a directory entry for classification
type DirEntry struct {
	Name    string
	IsDir   bool
	Path    string
}

// DirLister interface for directory traversal
type DirLister interface {
	ReadDir(path string) ([]DirEntry, error)
	FileReader(path string) ([]byte, error)
}

// FileSystemDirLister implements DirLister using os operations
type FileSystemDirLister struct{}

func (fs *FileSystemDirLister) ReadDir(path string) ([]DirEntry, error) {
	entries, err := filepath.Glob(path + "/*")
	if err != nil {
		return nil, err
	}
	var result []DirEntry
	for _, entry := range entries {
		info, err := os.Stat(entry)
		if err != nil {
			continue
		}
		result = append(result, DirEntry{
			Name:    filepath.Base(entry),
			IsDir:   info.IsDir(),
			Path:    entry,
		})
	}
	return result, nil
}

func (fs *FileSystemDirLister) FileReader(path string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented: use os.ReadFile")
}

// Classifier provides stateless, parallel-safe artifact classification
type Classifier struct {
	fileReader func(path string) ([]byte, error)
	dirLister  DirLister
}

// NewClassifier creates a new artifact classifier
func NewClassifier() *Classifier {
	return &Classifier{
		fileReader: func(path string) ([]byte, error) {
			return nil, fmt.Errorf("file reader not configured")
		},
		dirLister: nil,
	}
}

// SetFileReader sets the custom file reader function
func (c *Classifier) SetFileReader(reader func(path string) ([]byte, error)) {
	c.fileReader = reader
}

// SetDirLister sets the custom directory lister function
func (c *Classifier) SetDirLister(lister DirLister) {
	c.dirLister = lister
}

// DetectFileType detects the file type based on magic bytes/signatures
func (c *Classifier) DetectFileType(data []byte) ArtifactType {
	if len(data) < 16 {
		return ""
	}

	// Check for SQLite
	if bytes.HasPrefix(data, SQLiteSignature) {
		return ArtifactTypeHistory // Default to history, will be refined by schema inspection
	}

	// Check for MBOX
	if bytes.HasPrefix(data, MBOXSignature) {
		return ArtifactTypeEmailDefault
	}

	// Check for PST/OST
	if bytes.HasPrefix(data, PSTSignature) {
		return ArtifactTypeEmailMessage
	}

	// Check for JSON
	if bytes.HasPrefix(data, JSONStartMarkers) {
		return ArtifactTypeChromiumProfile
	}

	// Check for LevelDB
	if bytes.HasPrefix(data, LevelDBSignature) {
		return ArtifactTypeIndexedDB
	}

	// Check for MDB
	if bytes.HasPrefix(data, MDBSignature) {
		return ArtifactTypeEmailDefault
	}

	return ""
}

// Known artifact file patterns for browsers
var browserFilePatterns = map[AppType]map[ArtifactType][]string{
	AppChrome: {
		ArtifactTypeHistory:       {"History", "History-journal", "Visited Links"},
		ArtifactTypeCookies:       {"Cookies", "Cookies-journal", "Network/Cookies"},
		ArtifactTypeDownloads:     {"DownloadMetadata", "Downloads"},
		ArtifactTypeBookmarks:    {"Bookmarks", "Bookmarks-journal"},
		ArtifactTypeFormAutofill: {"Web Data", "Web Data-journal", " autofill"},
		ArtifactTypeLoginData:    {"Login Data", "Login Data-journal", "login_data"},
		ArtifactTypeCache:        {"Cache", "Cache2", "Code Cache", "GPUCache"},
		ArtifactTypeSearchHistory: {"Search History", "SearchProviders"},
		ArtifactTypePreferences:  {"Preferences", "Secure Preferences", "Local State"},
		ArtifactTypeExtensions:    {"Extensions", "Default/Extensions"},
	},
	AppEdge: {
		ArtifactTypeHistory:       {"History", "History-journal"},
		ArtifactTypeCookies:       {"Cookies", "Cookies-journal"},
		ArtifactTypeDownloads:     {"DownloadMetadata"},
		ArtifactTypeBookmarks:    {"Bookmarks", "Bookmarks-journal"},
		ArtifactTypeFormAutofill: {"Web Data", "Web Data-journal"},
		ArtifactTypeLoginData:    {"Login Data", "login_data"},
		ArtifactTypeCache:        {"Cache", "Cache2"},
		ArtifactTypePreferences:  {"Preferences", "Secure Preferences"},
	},
	AppFirefox: {
		ArtifactTypeHistory:       {"places.sqlite", "places.sqlite-wal", "places.sqlite-shm"},
		ArtifactTypeCookies:       {"cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm"},
		ArtifactTypeDownloads:    {"downloads.sqlite"},
		ArtifactTypeBookmarks:    {"bookmarks.sqlite", "bookmarks.json"},
		ArtifactTypeFormAutofill: {"formhistory.sqlite", "formhistory.sqlite-wal"},
		ArtifactTypeLoginData:    {"logins.json", "signons.sqlite", "key4.db"},
		ArtifactTypeCache:        {"cache2"},
		ArtifactTypeSearchHistory: {"search.sqlite", "search.json.mozlz4"},
		ArtifactTypePreferences:  {"prefs.js", "user.js", "times.json"},
		ArtifactTypeExtensions:    {"extensions.json", "addons.json"},
	},
	AppOpera: {
		ArtifactTypeHistory:       {"History", "History-journal"},
		ArtifactTypeCookies:       {"Cookies", "Cookies-journal"},
		ArtifactTypeDownloads:     {"DownloadMetadata"},
		ArtifactTypeBookmarks:    {"Bookmarks"},
		ArtifactTypeFormAutofill: {"Web Data"},
		ArtifactTypeLoginData:    {"Login Data"},
		ArtifactTypeCache:        {"Cache", "GPUCache"},
	},
	AppBrave: {
		ArtifactTypeHistory:       {"History", "History-journal"},
		ArtifactTypeCookies:       {"Cookies", "Cookies-journal"},
		ArtifactTypeDownloads:     {"DownloadMetadata"},
		ArtifactTypeBookmarks:    {"Bookmarks"},
		ArtifactTypeFormAutofill: {"Web Data"},
		ArtifactTypeLoginData:    {"Login Data"},
		ArtifactTypeCache:        {"Cache", "GPUCache"},
	},
}

// Communication app file patterns
var communicationFilePatterns = map[AppType]map[ArtifactType][]string{
	AppOutlook: {
		ArtifactTypePSTFile:  {"*.pst"},
		ArtifactTypeOSTFile: {"*.ost"},
	},
	AppThunderbird: {
		ArtifactTypeThunderbirdMail:    {"*.mbox", "Inbox", "Sent", "Drafts", "Trash"},
		ArtifactTypeThunderbirdProfile: {"prefs.js", "profiles.ini"},
	},
	AppWhatsApp: {
		ArtifactTypeWhatsAppChat:  {"msgstore.db", "msgstore.db.crypt14", "msgstore.db.crypt15", "msgstore.db.crypt16"},
		ArtifactTypeWhatsAppMedia: {"Media", "WhatsApp Images", "WhatsApp Audio", "WhatsApp Video", "WhatsApp Documents"},
	},
	AppTelegram: {
		ArtifactTypeTelegramChat:   {"messages.db", "messages%d.db"},
		ArtifactTypeTelegramMedia: {"tdata", "account(", "chats", "documents"},
		ArtifactTypeTelegramData:  {"tdata", "settings.dat", "key_data"},
	},
	AppSlack: {
		ArtifactTypeSlackMessages: {"slack-db", "index", "*.sqlite"},
		ArtifactTypeSlackFiles:   {"Cache", "Files"},
	},
	AppTeams: {
		ArtifactTypeTeamsMessages: {"IndexedDB", "*.sqlite"},
		ArtifactTypeTeamsFiles:   {"Files", "media"},
	},
}

// Profile detection patterns
var profilePatterns = map[AppType][]string{
	AppChrome:     {"Default", "Default(", "Profile", "Profile(", "System Profile"},
	AppEdge:      {"Default", "Default(", "Profile", "Profile("},
	AppFirefox:   {"Profiles", "*.default*", "*.release*", "*.esr*"},
	AppOpera:     {"Default", "Default(", "Profile", "Profile("},
	AppBrave:     {"Default", "Default(", "Profile", "Profile("},
	AppThunderbird: {"Profiles", "*.default*"},
}

// Directory heuristics for app detection
var directoryHeuristics = []struct {
	App        AppType
	OSPatterns []string
	PathIndicators []string
	DirIndicators []string
}{
	{
		App:        AppChrome,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"google/chrome/user data",
			"google/chrome/profiles",
			"chromium/user data",
			"chromium/profiles",
		},
		DirIndicators: []string{"Default", "System Profile", "Profile"},
	},
	{
		App:        AppEdge,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"microsoft edge/user data",
			"microsoft edge/profiles",
		},
		DirIndicators: []string{"Default", "Profile"},
	},
	{
		App:        AppFirefox,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"mozilla/firefox/profiles",
			"firefox/profiles",
		},
		DirIndicators: []string{".default", ".release", ".esr", "profiles"},
	},
	{
		App:        AppOpera,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"opera software/opera stable",
			"opera/user data",
		},
		DirIndicators: []string{"Default", "Profile"},
	},
	{
		App:        AppBrave,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"brave software/brave-browser/user data",
			"brave-browser/user data",
		},
		DirIndicators: []string{"Default", "Profile"},
	},
	{
		App:        AppOutlook,
		OSPatterns: []string{"windows"},
		PathIndicators: []string{
			"microsoft/outlook",
			"outlook",
			"microsoft office/outlook",
		},
		DirIndicators: []string{"Outlook", "*.pst", "*.ost"},
	},
	{
		App:        AppThunderbird,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"thunderbird/profiles",
			"mozilla/thunderbird/profiles",
		},
		DirIndicators: []string{"Profiles", ".default"},
	},
	{
		App:        AppWhatsApp,
		OSPatterns: []string{"windows", "macos"},
		PathIndicators: []string{
			"whatsapp/desktop",
			"whatsapp",
			"messenger/whatsapp",
		},
		DirIndicators: []string{"msgstore.db", "Media", "ChatStorage"},
	},
	{
		App:        AppTelegram,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"telegram desktop",
			"telegram",
			"tdesktop",
		},
		DirIndicators: []string{"tdata", "messages.db"},
	},
	{
		App:        AppSlack,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"slack",
			"utilities/slack",
		},
		DirIndicators: []string{"slack-cache", "IndexedDB", "localStorage"},
	},
	{
		App:        AppTeams,
		OSPatterns: []string{"windows", "macos", "linux"},
		PathIndicators: []string{
			"microsoft teams",
			"teams",
		},
		DirIndicators: []string{"Cache", "IndexedDB", "GPUCache"},
	},
}

// InspectSQLiteSchema inspects SQLite database schema to classify artifact type
func (c *Classifier) InspectSQLiteSchema(dbPath string) (ArtifactType, error) {
	data, err := c.fileReader(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to read database: %w", err)
	}

	// Verify it's a SQLite file
	if !bytes.HasPrefix(data, SQLiteSignature) {
		return "", fmt.Errorf("not a SQLite database")
	}

	// Extended table patterns for artifact detection
	tablePatterns := map[ArtifactType][]string{
		// Browser patterns
		ArtifactTypeHistory:        {"urls", "visits", "url", "visit", "moz_places", "place_id", "chrome_url_visits", "context_visits"},
		ArtifactTypeCookies:        {"cookies", "cookie", "moz_cookies", "chrome_cookies", "network_cookies"},
		ArtifactTypeDownloads:      {"downloads", "download", "download_url_chunks", "downloads_url"},
		ArtifactTypeBookmarks:      {"bookmarks", "bookmark", "moz_bookmarks", "bookmark_folders"},
		ArtifactTypeFormAutofill:   {"autofill", "form_autofill", "credit_cards", "webkit_form_history", "moz_formhistory", "autofill_history"},
		ArtifactTypeSearchHistory:   {"keyword_search_terms", "moz_input_history", "search_engines", "search_history"},
		ArtifactTypeLoginData:       {"logins", "password", "login", "chrome_logins", "encrypted_token", "meta"},
		ArtifactTypeWebApps:         {"web_apps", "webapp", "app_install_states"},

		// Communication patterns
		ArtifactTypeWhatsAppChat:  {"messages", "chat", "message", "conversation", "messages_journal"},
		ArtifactTypeTelegramChat:   {"messages", "chats", "dialogs", "messages_journal"},
		ArtifactTypeSlackMessages:  {"messages", "conversations", "slack_messages"},
		ArtifactTypeTeamsMessages:  {"messages", "teams_messages", "conversation"},
		ArtifactTypeThunderbirdMail: {"messages", "folder", "nntp", "imap", "pop3", "mbox_messages"},

		// Extension patterns
		ArtifactTypeExtensions:     {"extensions", "installs", "enabled_extensions"},
	}

	// Simple pattern matching on raw data for table names
	dataStr := string(data)

	for artifactType, patterns := range tablePatterns {
		for _, pattern := range patterns {
			if strings.Contains(dataStr, pattern) {
				return artifactType, nil
			}
		}
	}

	// Default to history if we can't determine
	return ArtifactTypeHistory, nil
}

// DetectOS detects the operating system from the path
func DetectOS(path string) OSType {
	pathLower := strings.ToLower(path)

	// Windows patterns
	if strings.Contains(pathLower, "appdata") ||
		strings.Contains(pathLower, "/users/") && strings.Contains(pathLower, "\\") ||
		strings.Contains(pathLower, "\\users\\") ||
		strings.Contains(pathLower, "program files") ||
		strings.Contains(pathLower, "programdata") {
		return OSWindows
	}

	// macOS patterns
	if strings.Contains(pathLower, "/users/") ||
		strings.Contains(pathLower, "library/application support") ||
		strings.Contains(pathLower, "library/caches") {
		return OSMac
	}

	// Linux patterns
	if strings.Contains(pathLower, "/home/") ||
		strings.Contains(pathLower, "/.config/") ||
		strings.Contains(pathLower, "/.local/share/") ||
		strings.Contains(pathLower, "/.cache/") {
		return OSLinux
	}

	// iOS patterns (jailbroken)
	if strings.Contains(pathLower, "/var/mobile/") ||
		strings.Contains(pathLower, "/private/var/mobile/") {
		return OSiOS
	}

	// Android patterns
	if strings.Contains(pathLower, "/data/data/") ||
		strings.Contains(pathLower, "/data/user/") ||
		strings.Contains(pathLower, "/sdcard/") {
		return OSAndroid
	}

	return OSWindows // Default assumption
}

// DetectAppFromPath detects the application from directory path
func DetectAppFromPath(path string) AppType {
	pathLower := strings.ToLower(path)

	// Order matters - more specific patterns first

	// WhatsApp Desktop
	if strings.Contains(pathLower, "whatsapp/desktop") ||
		strings.Contains(pathLower, "whatsapp") && strings.Contains(pathLower, "appdata") {
		return AppWhatsApp
	}

	// Telegram Desktop
	if strings.Contains(pathLower, "telegram desktop") ||
		strings.Contains(pathLower, "/telegram") ||
		strings.Contains(pathLower, "tdesktop") {
		return AppTelegram
	}

	// Microsoft Teams
	if strings.Contains(pathLower, "microsoft teams") ||
		strings.Contains(pathLower, "/teams/") && strings.Contains(pathLower, "appdata") {
		return AppTeams
	}

	// Slack
	if strings.Contains(pathLower, "/slack/") && (strings.Contains(pathLower, "appdata") || strings.Contains(pathLower, ".config")) {
		return AppSlack
	}

	// Thunderbird
	if strings.Contains(pathLower, "thunderbird") {
		return AppThunderbird
	}

	// Outlook
	if strings.Contains(pathLower, "outlook") && strings.Contains(pathLower, "appdata") {
		return AppOutlook
	}

	// Edge (before Chrome to avoid false positives)
	if strings.Contains(pathLower, "microsoft edge") ||
		strings.Contains(pathLower, "/edge/") {
		return AppEdge
	}

	// Brave
	if strings.Contains(pathLower, "brave") {
		return AppBrave
	}

	// Opera
	if strings.Contains(pathLower, "opera") {
		return AppOpera
	}

	// Firefox
	if strings.Contains(pathLower, "firefox") || strings.Contains(pathLower, "mozilla") {
		return AppFirefox
	}

	// Chrome (check last as it's most common)
	if strings.Contains(pathLower, "chrome") || strings.Contains(pathLower, "chromium") {
		return AppChrome
	}

	// Gmail (offline/backup)
	if strings.Contains(pathLower, "gmail") && strings.Contains(pathLower, "offline") {
		return AppGmail
	}

	return AppUnknown
}

// DetectProfile detects the profile name from browser directory path
func DetectProfile(path string, app AppType) string {
	pathLower := strings.ToLower(path)
	dir := filepath.Base(path)

	// Chrome/Edge/Brave/Opera profile detection
	if app == AppChrome || app == AppEdge || app == AppBrave || app == AppOpera {
		// Check for Default profile
		if strings.Contains(pathLower, "default") {
			return "Default"
		}
		// Check for Profile patterns like Profile 1, Profile 2
		if strings.Contains(pathLower, "profile") {
			parts := strings.Split(dir, "(")
			if len(parts) > 1 {
				return strings.TrimSuffix(parts[1], ")")
			}
			return dir
		}
		// Check for numbered patterns like "Default"
		if strings.HasPrefix(dir, "Profile") {
			return dir
		}
	}

	// Firefox profile detection
	if app == AppFirefox {
		// Get the profile folder name
		parts := strings.Split(dir, ".")
		if len(parts) >= 2 {
			// Pattern: xxxxxxxx.default or xxxxxxxx.default-release
			for i, part := range parts {
				if strings.Contains(part, "default") || strings.Contains(part, "release") || strings.Contains(part, "esr") {
					return strings.Join(parts[i:], ".")
				}
			}
		}
		// Check if it's a profile path
		if strings.Contains(pathLower, "profiles") {
			return dir
		}
	}

	// Thunderbird profile detection
	if app == AppThunderbird {
		if strings.Contains(pathLower, "profiles") {
			parts := strings.Split(dir, ".")
			if len(parts) >= 2 {
				return strings.Join(parts[1:], ".")
			}
		}
	}

	return ""
}

// DetectBrowserArtifact classifies a browser artifact file
func (c *Classifier) DetectBrowserArtifact(file models.ForensicFile) (models.ForensicFile, error) {
	result := file

	data, err := c.fileReader(file.Path)
	if err != nil {
		result.Category = string(ArtifactTypeHistory)
		return result, nil
	}

	artifactType := c.DetectFileType(data)
	result.Category = string(artifactType)

	// If it's SQLite, inspect schema for more specific classification
	if artifactType == ArtifactTypeHistory || bytes.HasPrefix(data, SQLiteSignature) {
		detectedType, err := c.InspectSQLiteSchema(file.Path)
		if err == nil {
			result.Category = string(detectedType)
		}
	}

	// Additional path-based heuristics for browser type
	filename := strings.ToLower(filepath.Base(file.Path))
	path := strings.ToLower(file.Path)

	// Detect Chrome/Chromium specific files
	if strings.Contains(path, "chrome") || strings.Contains(path, "chromium") {
		result.Browser = "chrome"
		if strings.Contains(filename, "history") {
			result.Category = string(ArtifactTypeHistory)
		} else if strings.Contains(filename, "cookies") {
			result.Category = string(ArtifactTypeCookies)
		} else if strings.Contains(filename, "download") {
			result.Category = string(ArtifactTypeDownloads)
		} else if strings.Contains(filename, "bookmark") {
			result.Category = string(ArtifactTypeBookmarks)
		} else if strings.Contains(filename, "login") || strings.Contains(filename, "autofill") {
			result.Category = string(ArtifactTypeFormAutofill)
		}
	}

	// Detect Firefox specific files
	if strings.Contains(path, "firefox") || strings.Contains(path, "mozilla") {
		result.Browser = "firefox"
		if strings.Contains(filename, "places") {
			result.Category = string(ArtifactTypeHistory)
		} else if strings.Contains(filename, "cookies") {
			result.Category = string(ArtifactTypeCookies)
		}
	}

	// Detect Edge specific files
	if strings.Contains(path, "edge") {
		result.Browser = "edge"
	}

	return result, nil
}

// DetectCommunicationArtifact classifies a communication artifact file
func (c *Classifier) DetectCommunicationArtifact(file models.ForensicFile) (models.ForensicFile, error) {
	result := file

	data, err := c.fileReader(file.Path)
	if err != nil {
		result.Category = string(ArtifactTypeEmailDefault)
		return result, nil
	}

	artifactType := c.DetectFileType(data)
	path := strings.ToLower(file.Path)
	filename := strings.ToLower(filepath.Base(file.Path))

	// Check for Gmail folder structure in path
	if strings.Contains(path, "[gmail]") || strings.Contains(path, "gmail") {
		if strings.Contains(filename, "draft") || strings.Contains(path, "drafts") {
			result.Category = string(ArtifactTypeGmailDrafts)
		} else if strings.Contains(filename, "sent") || strings.Contains(path, "sent mail") {
			result.Category = string(ArtifactTypeGmailSent)
		} else if strings.Contains(filename, "trash") || strings.Contains(path, "trash") {
			result.Category = string(ArtifactTypeGmailTrash)
		} else if strings.Contains(path, "all mail") {
			result.Category = string(ArtifactTypeGmailAllMail)
		} else {
			result.Category = string(ArtifactTypeEmailDefault)
		}
	} else if artifactType == ArtifactTypeEmailDefault {
		// MBOX file detected
		result.Category = string(ArtifactTypeMBOXFile)
	} else if artifactType == ArtifactTypeEmailMessage {
		// PST/OST file detected
		if strings.HasSuffix(filename, ".pst") {
			result.Category = string(ArtifactTypePSTFile)
		} else if strings.HasSuffix(filename, ".ost") {
			result.Category = string(ArtifactTypeOSTFile)
		} else {
			result.Category = string(ArtifactTypeEmailMessage)
		}
	}

	// Check for WhatsApp
	if strings.Contains(path, "whatsapp") {
		if strings.Contains(filename, "msgstore") {
			result.Category = string(ArtifactTypeWhatsAppChat)
		} else if strings.Contains(path, "media") || strings.Contains(filename, "media") {
			result.Category = string(ArtifactTypeWhatsAppMedia)
		}
	}

	// Check for Telegram
	if strings.Contains(path, "telegram") {
		if strings.Contains(filename, "messages") {
			result.Category = string(ArtifactTypeTelegramChat)
		} else if strings.Contains(path, "tdata") || strings.Contains(filename, "tdata") {
			result.Category = string(ArtifactTypeTelegramData)
		} else if strings.Contains(path, "media") {
			result.Category = string(ArtifactTypeTelegramMedia)
		}
	}

	// Check for Slack
	if strings.Contains(path, "slack") {
		if strings.Contains(filename, "db") || strings.Contains(filename, "index") {
			result.Category = string(ArtifactTypeSlackMessages)
		} else if strings.Contains(path, "cache") || strings.Contains(path, "files") {
			result.Category = string(ArtifactTypeSlackFiles)
		}
	}

	// Check for Teams
	if strings.Contains(path, "teams") {
		if strings.Contains(filename, "db") || strings.Contains(path, "indexeddb") {
			result.Category = string(ArtifactTypeTeamsMessages)
		} else if strings.Contains(path, "files") || strings.Contains(path, "media") {
			result.Category = string(ArtifactTypeTeamsFiles)
		}
	}

	// Check for account files
	accountIndicators := []string{"account", "profile", "identities"}
	for _, indicator := range accountIndicators {
		if strings.Contains(path, indicator) {
			result.Category = string(ArtifactTypeEmailAccount)
			break
		}
	}

	// Try to parse JSON for account detection
	if bytes.HasPrefix(data, JSONStartMarkers) {
		var jsonData map[string]interface{}
		if err := json.Unmarshal(data, &jsonData); err == nil {
			if _, hasEmail := jsonData["email"]; hasEmail {
				result.Category = string(ArtifactTypeEmailAccount)
			}
			if _, hasAccountID := jsonData["account_id"]; hasAccountID {
				result.Category = string(ArtifactTypeEmailAccount)
			}
			if _, hasSMTP := jsonData["smtp"]; hasSMTP {
				result.Category = string(ArtifactTypeEmailAccount)
			}
		}
	}

	return result, nil
}

// AnalyzeDirectory analyzes a directory and returns structured results
func (c *Classifier) AnalyzeDirectory(dirPath string) ([]DirectoryResult, error) {
	var results []DirectoryResult

	// Skip if no directory lister configured
	if c.dirLister == nil {
		return results, fmt.Errorf("directory lister not configured")
	}

	// Get OS and App from path
	detectedOS := DetectOS(dirPath)
	detectedApp := DetectAppFromPath(dirPath)

	// If app is unknown, try to determine from directory contents
	if detectedApp == AppUnknown {
		entries, err := c.dirLister.ReadDir(dirPath)
		if err == nil {
			detectedApp = detectAppFromContents(entries, dirPath)
		}
	}

	// Get profile if applicable
	profile := DetectProfile(dirPath, detectedApp)

	// Read directory contents
	entries, err := c.dirLister.ReadDir(dirPath)
	if err != nil {
		return results, fmt.Errorf("failed to read directory: %w", err)
	}

	// Collect relevant files
	var relevantFiles []string
	var subDirs []string

	for _, entry := range entries {
		if entry.IsDir {
			subDirs = append(subDirs, entry.Name)
		} else {
			relevantFiles = append(relevantFiles, entry.Name)
		}
	}

	// Determine category based on files
	category := determineCategory(detectedApp, relevantFiles, subDirs)

	result := DirectoryResult{
		Path:     dirPath,
		OS:       string(detectedOS),
		App:      string(detectedApp),
		Profile:  profile,
		Category: category,
		Files:    relevantFiles,
		Metadata: map[string]interface{}{
			"subdirectories": subDirs,
			"fileCount":     len(relevantFiles),
			"dirCount":      len(subDirs),
		},
	}

	results = append(results, result)

	// If this is a browser profile directory, also analyze subdirectories
	if detectedApp == AppChrome || detectedApp == AppEdge || detectedApp == AppBrave || detectedApp == AppOpera {
		results = append(results, c.analyzeChromiumSubdirs(dirPath, detectedOS, detectedApp)...)
	}

	// If this is Firefox profiles directory
	if detectedApp == AppFirefox && strings.Contains(dirPath, "profiles") {
		results = append(results, c.analyzeFirefoxProfiles(dirPath, detectedOS)...)
	}

	return results, nil
}

// analyzeChromiumSubdirs analyzes subdirectories of Chromium-based browsers
func (c *Classifier) analyzeChromiumSubdirs(basePath string, os OSType, app AppType) []DirectoryResult {
	var results []DirectoryResult

	entries, err := c.dirLister.ReadDir(basePath)
	if err != nil {
		return results
	}

	for _, entry := range entries {
		if !entry.IsDir {
			continue
		}

		subPath := filepath.Join(basePath, entry.Name)

		// Check for known subdirectories
		entryLower := strings.ToLower(entry.Name)

		var category string
		switch {
		case strings.Contains(entryLower, "cache") || strings.Contains(entryLower, "gpu cache"):
			category = string(ArtifactTypeCache)
		case strings.Contains(entryLower, "local storage"):
			category = string(ArtifactTypeLocalStorage)
		case strings.Contains(entryLower, "indexeddb"):
			category = string(ArtifactTypeIndexedDB)
		case strings.Contains(entryLower, "extension"):
			category = string(ArtifactTypeExtensions)
		case strings.Contains(entryLower, "code cache"):
			category = string(ArtifactTypeCache)
		case strings.Contains(entryLower, "service worker"):
			category = string(ArtifactTypeServiceWorkers)
		default:
			continue // Skip unknown subdirectories
		}

		// Read files in this subdirectory
		subEntries, _ := c.dirLister.ReadDir(subPath)
		var files []string
		for _, se := range subEntries {
			if !se.IsDir {
				files = append(files, se.Name)
			}
		}

		results = append(results, DirectoryResult{
			Path:     subPath,
			OS:       string(os),
			App:      string(app),
			Profile:  DetectProfile(basePath, app),
			Category: category,
			Files:    files,
		})
	}

	return results
}

// analyzeFirefoxProfiles analyzes Firefox profile directories
func (c *Classifier) analyzeFirefoxProfiles(basePath string, os OSType) []DirectoryResult {
	var results []DirectoryResult

	entries, err := c.dirLister.ReadDir(basePath)
	if err != nil {
		return results
	}

	for _, entry := range entries {
		if !entry.IsDir {
			continue
		}

		profilePath := filepath.Join(basePath, entry.Name)

		// Determine profile name
		profileName := entry.Name
		if strings.HasPrefix(entry.Name, ".") {
			parts := strings.Split(entry.Name, ".")
			if len(parts) >= 2 {
				profileName = parts[len(parts)-1]
			}
		}

		// Read profile contents
		profileEntries, _ := c.dirLister.ReadDir(profilePath)
		var files []string
		var category string

		for _, pe := range profileEntries {
			if pe.IsDir {
				continue
			}
			files = append(files, pe.Name)

			// Determine category based on files
			nameLower := strings.ToLower(pe.Name)
			switch {
			case strings.Contains(nameLower, "places.sqlite"):
				category = string(ArtifactTypeHistory)
			case strings.Contains(nameLower, "cookies.sqlite"):
				category = string(ArtifactTypeCookies)
			case strings.Contains(nameLower, "formhistory.sqlite"):
				category = string(ArtifactTypeFormAutofill)
			case strings.Contains(nameLower, "logins.json"):
				category = string(ArtifactTypeLoginData)
			case strings.Contains(nameLower, "bookmarks"):
				category = string(ArtifactTypeBookmarks)
			case strings.Contains(nameLower, "search.sqlite"):
				category = string(ArtifactTypeSearchHistory)
			}
		}

		results = append(results, DirectoryResult{
			Path:     profilePath,
			OS:       string(os),
			App:      string(AppFirefox),
			Profile:  profileName,
			Category: category,
			Files:    files,
		})
	}

	return results
}

// detectAppFromContents detects app from directory contents
func detectAppFromContents(entries []DirEntry, path string) AppType {
	pathLower := strings.ToLower(path)

	// Check for browser indicators
	for _, entry := range entries {
		nameLower := strings.ToLower(entry.Name)

		// Chrome patterns
		if nameLower == "history" || nameLower == "cookies" || nameLower == "bookmarks" ||
			nameLower == "login data" || nameLower == "web data" {
			if !strings.Contains(pathLower, "firefox") && !strings.Contains(pathLower, "mozilla") {
				// Check if it's in a browser user data folder
				if strings.Contains(pathLower, "chrome") || strings.Contains(pathLower, "edge") ||
					strings.Contains(pathLower, "brave") || strings.Contains(pathLower, "opera") ||
					strings.Contains(pathLower, "chromium") {
					if strings.Contains(pathLower, "edge") {
						return AppEdge
					}
					if strings.Contains(pathLower, "brave") {
						return AppBrave
					}
					if strings.Contains(pathLower, "opera") {
						return AppOpera
					}
					return AppChrome
				}
			}
		}

		// Firefox patterns
		if nameLower == "places.sqlite" || nameLower == "cookies.sqlite" ||
			nameLower == "formhistory.sqlite" || strings.Contains(nameLower, ".default") {
			return AppFirefox
		}

		// Outlook PST/OST
		if strings.HasSuffix(nameLower, ".pst") || strings.HasSuffix(nameLower, ".ost") {
			return AppOutlook
		}

		// Thunderbird
		if nameLower == "inbox" || nameLower == "sent" || nameLower == "drafts" ||
			strings.HasSuffix(nameLower, ".mbox") {
			return AppThunderbird
		}

		// WhatsApp
		if nameLower == "msgstore.db" || strings.Contains(nameLower, "whatsapp") && entry.IsDir {
			return AppWhatsApp
		}

		// Telegram
		if nameLower == "tdata" || nameLower == "messages.db" {
			return AppTelegram
		}

		// Slack
		if strings.Contains(nameLower, "slack") {
			return AppSlack
		}

		// Teams
		if strings.Contains(nameLower, "teams") {
			return AppTeams
		}
	}

	return AppUnknown
}

// determineCategory determines the artifact category from files
func determineCategory(app AppType, files []string, subDirs []string) string {
	allNames := append(files, subDirs...)
	namesLower := make([]string, len(allNames))
	for i, name := range allNames {
		namesLower[i] = strings.ToLower(name)
	}

	patterns, ok := browserFilePatterns[app]
	if ok {
		for category, patternList := range patterns {
			for _, pattern := range patternList {
				patternLower := strings.ToLower(pattern)
				for _, name := range namesLower {
					if strings.Contains(name, patternLower) {
						return string(category)
					}
				}
			}
		}
	}

	// Check communication patterns
	commPatterns, ok := communicationFilePatterns[app]
	if ok {
		for category, patternList := range commPatterns {
			for _, pattern := range patternList {
				patternLower := strings.ToLower(pattern)
				for _, name := range namesLower {
					if strings.Contains(name, patternLower) {
						return string(category)
					}
				}
			}
		}
	}

	// Default category based on app type
	switch app {
	case AppChrome, AppEdge, AppBrave, AppOpera:
		return string(ArtifactTypeChromiumProfile)
	case AppFirefox:
		return string(ArtifactTypeHistory)
	case AppOutlook:
		return string(ArtifactTypeEmailMessage)
	case AppThunderbird:
		return string(ArtifactTypeThunderbirdMail)
	case AppWhatsApp:
		return string(ArtifactTypeWhatsAppChat)
	case AppTelegram:
		return string(ArtifactTypeTelegramChat)
	case AppSlack:
		return string(ArtifactTypeSlackMessages)
	case AppTeams:
		return string(ArtifactTypeTeamsMessages)
	}

	return string(ArtifactTypeHistory)
}

// DetectDirectory detects artifacts in a directory using directory-aware heuristics
func (c *Classifier) DetectDirectory(dirPath string) ([]DirectoryResult, error) {
	return c.AnalyzeDirectory(dirPath)
}

// ScanRootDirectories scans common root directories for artifacts
func (c *Classifier) ScanRootDirectories(rootPath string) ([]DirectoryResult, error) {
	var results []DirectoryResult

	if c.dirLister == nil {
		return results, fmt.Errorf("directory lister not configured")
	}

	// Common browser root paths per OS
	browserRoots := map[OSType][]string{
		OSWindows: {
			filepath.Join(rootPath, "Google", "Chrome", "User Data"),
			filepath.Join(rootPath, "Microsoft", "Edge", "User Data"),
			filepath.Join(rootPath, "Mozilla", "Firefox", "Profiles"),
			filepath.Join(rootPath, "Opera Software", "Opera Stable"),
			filepath.Join(rootPath, "BraveSoftware", "Brave-Browser", "User Data"),
		},
		OSMac: {
			filepath.Join(rootPath, "Library", "Application Support", "Google", "Chrome"),
			filepath.Join(rootPath, "Library", "Application Support", "Microsoft Edge"),
			filepath.Join(rootPath, "Library", "Application Support", "Firefox", "Profiles"),
			filepath.Join(rootPath, "Library", "Application Support", "com.operasoftware.Opera"),
			filepath.Join(rootPath, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
		},
		OSLinux: {
			filepath.Join(rootPath, ".config", "google-chrome"),
			filepath.Join(rootPath, ".config", "microsoft-edge"),
			filepath.Join(rootPath, ".mozilla", "firefox"),
			filepath.Join(rootPath, ".config", "opera"),
			filepath.Join(rootPath, ".config", "BraveSoftware", "Brave-Browser"),
		},
	}

	// Communication app roots
	communicationRoots := map[OSType][]string{
		OSWindows: {
			filepath.Join(rootPath, "Microsoft", "Outlook"),
			filepath.Join(rootPath, "Microsoft", "Teams"),
			filepath.Join(rootPath, "Slack"),
			filepath.Join(rootPath, "WhatsApp"),
			filepath.Join(rootPath, "Telegram Desktop"),
		},
		OSMac: {
			filepath.Join(rootPath, "Library", "Application Support", "Microsoft Outlook"),
			filepath.Join(rootPath, "Library", "Application Support", "Slack"),
			filepath.Join(rootPath, "Library", "Containers", "com.whatsapp.WhatsApp"),
			filepath.Join(rootPath, "Library", "Application Support", "Telegram Desktop"),
		},
		OSLinux: {
			filepath.Join(rootPath, ".config", "microsoft-team"),
			filepath.Join(rootPath, ".config", "Slack"),
			filepath.Join(rootPath, ".local", "share", "TelegramDesktop"),
		},
	}

	detectedOS := DetectOS(rootPath)

	// Scan browser roots
	for _, browserRoot := range browserRoots[detectedOS] {
		entries, err := c.dirLister.ReadDir(browserRoot)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir {
				continue
			}

			profilePath := filepath.Join(browserRoot, entry.Name)
			profileResults, err := c.AnalyzeDirectory(profilePath)
			if err == nil {
				results = append(results, profileResults...)
			}
		}
	}

	// Scan communication roots
	for _, commRoot := range communicationRoots[detectedOS] {
		commResults, commErr := c.AnalyzeDirectory(commRoot)
		if commErr == nil && len(commResults) > 0 {
			results = append(results, commResults...)
		}
	}

	return results, nil
}

// ClassifyBrowserArtifact classifies a forensic file into the appropriate browser category
func ClassifyBrowserArtifact(file models.ForensicFile) models.ForensicFile {
	result := file

	filename := strings.ToLower(filepath.Base(file.Path))
	path := strings.ToLower(file.Path)

	// Determine browser type
	if strings.Contains(path, "chrome") || strings.Contains(path, "chromium") {
		result.Browser = "chrome"
	} else if strings.Contains(path, "firefox") || strings.Contains(path, "mozilla") {
		result.Browser = "firefox"
	} else if strings.Contains(path, "edge") {
		result.Browser = "edge"
	} else if strings.Contains(path, "opera") {
		result.Browser = "opera"
	} else if strings.Contains(path, "brave") {
		result.Browser = "brave"
	}

	// Classify based on filename patterns
	switch {
	case strings.Contains(filename, "history") || strings.Contains(filename, "places"):
		result.Category = string(ArtifactTypeHistory)
	case strings.Contains(filename, "cookie"):
		result.Category = string(ArtifactTypeCookies)
	case strings.Contains(filename, "download"):
		result.Category = string(ArtifactTypeDownloads)
	case strings.Contains(filename, "bookmark"):
		result.Category = string(ArtifactTypeBookmarks)
	case strings.Contains(filename, "cache") || strings.Contains(filename, "cache2"):
		result.Category = string(ArtifactTypeCache)
	case strings.Contains(filename, "login") || strings.Contains(filename, "autofill") || strings.Contains(filename, "form"):
		result.Category = string(ArtifactTypeFormAutofill)
	case strings.Contains(filename, "search") || strings.Contains(filename, "keyword"):
		result.Category = string(ArtifactTypeSearchHistory)
	case strings.Contains(filename, "extension") || strings.Contains(filename, "extensions"):
		result.Category = string(ArtifactTypeChromiumExt)
	case strings.Contains(filename, "preferences") || strings.Contains(filename, "pref"):
		result.Category = string(ArtifactTypeChromiumProfile)
	default:
		result.Category = "browser_db"
	}

	return result
}

// ClassifyCommunicationArtifact classifies a forensic file into the appropriate communication category
func ClassifyCommunicationArtifact(file models.ForensicFile) models.ForensicFile {
	result := file

	filename := strings.ToLower(filepath.Base(file.Path))
	path := strings.ToLower(file.Path)

	// Detect Gmail folders
	if strings.Contains(path, "[gmail]") || strings.Contains(path, "gmail/all mail") {
		if strings.Contains(filename, "draft") || strings.Contains(path, "drafts") {
			result.Category = string(ArtifactTypeGmailDrafts)
		} else if strings.Contains(filename, "sent") || strings.Contains(path, "sent mail") {
			result.Category = string(ArtifactTypeGmailSent)
		} else if strings.Contains(filename, "trash") || strings.Contains(path, "trash") {
			result.Category = string(ArtifactTypeGmailTrash)
		} else {
			result.Category = string(ArtifactTypeEmailDefault)
		}
	} else if strings.Contains(path, "outlook") || strings.Contains(path, "pst") || strings.Contains(path, "ost") {
		if strings.HasSuffix(filename, ".pst") {
			result.Category = string(ArtifactTypePSTFile)
		} else if strings.HasSuffix(filename, ".ost") {
			result.Category = string(ArtifactTypeOSTFile)
		} else if strings.Contains(filename, "draft") {
			result.Category = string(ArtifactTypeGmailDrafts)
		} else if strings.Contains(filename, "sent") {
			result.Category = string(ArtifactTypeGmailSent)
		} else if strings.Contains(filename, "trash") || strings.Contains(filename, "deleted") {
			result.Category = string(ArtifactTypeGmailTrash)
		} else {
			result.Category = string(ArtifactTypeEmailMessage)
		}
	} else if strings.HasPrefix(filename, "mbox") || strings.Contains(path, "mbox") {
		result.Category = string(ArtifactTypeMBOXFile)
	} else if strings.Contains(path, "account") || strings.Contains(path, "profile") {
		result.Category = string(ArtifactTypeEmailAccount)
	} else if strings.Contains(path, "whatsapp") {
		if strings.Contains(filename, "msgstore") {
			result.Category = string(ArtifactTypeWhatsAppChat)
		} else {
			result.Category = string(ArtifactTypeWhatsAppMedia)
		}
	} else if strings.Contains(path, "telegram") {
		if strings.Contains(filename, "messages") {
			result.Category = string(ArtifactTypeTelegramChat)
		} else {
			result.Category = string(ArtifactTypeTelegramData)
		}
	} else {
		result.Category = string(ArtifactTypeEmailDefault)
	}

	return result
}

// DirectoryResultsToJSON converts directory results to JSON format
func DirectoryResultsToJSON(results []DirectoryResult) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal results: %w", err)
	}
	return string(data), nil
}

// IsSQLiteFile checks if the data represents a SQLite database
func IsSQLiteFile(data []byte) bool {
	return len(data) >= 16 && bytes.HasPrefix(data, SQLiteSignature)
}

// IsMBOXFile checks if the data represents an MBOX email file
func IsMBOXFile(data []byte) bool {
	return len(data) >= 5 && bytes.HasPrefix(data, MBOXSignature)
}

// IsPSTFile checks if the data represents a PST/OST file
func IsPSTFile(data []byte) bool {
	return len(data) >= 3 && bytes.HasPrefix(data, PSTSignature)
}

// IsJSONFile checks if the data represents a JSON file
func IsJSONFile(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// IsLevelDB checks if the data represents a LevelDB database
func IsLevelDB(data []byte) bool {
	return len(data) >= 7 && bytes.HasPrefix(data, LevelDBSignature)
}

// CopyFileWithHash copies a file and computes its hash (reader interface version)
func CopyFileWithHash(reader io.Reader, destPath string) ([]byte, int64, error) {
	return nil, 0, fmt.Errorf("not implemented: use os-specific implementation")
}
