package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	checkInterval = 24 * time.Hour
	cacheFileName = "update_check.json"
	cacheDirName  = ".peep"
)

// cacheEntry represents the cached update check result.
type cacheEntry struct {
	LastCheck     time.Time `json:"last_check"`
	LatestVersion string    `json:"latest_version"`
}

// CacheDir returns ~/.peep/, creating it if needed.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, cacheDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

// cachePath returns the full path to the cache file.
func cachePath() (string, error) {
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, cacheFileName), nil
}

// ShouldCheck returns true if enough time has passed since the
// last update check (> 24 hours) or if no check has been recorded.
func ShouldCheck() bool {
	entry, err := readCache()
	if err != nil {
		return true // no cache or corrupt → check
	}
	return time.Since(entry.LastCheck) > checkInterval
}

// SaveCheckResult writes the latest version and current timestamp
// to the cache file.
func SaveCheckResult(latestVersion string) error {
	path, err := cachePath()
	if err != nil {
		return err
	}

	entry := cacheEntry{
		LastCheck:     time.Now(),
		LatestVersion: latestVersion,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// GetCachedResult returns the cached latest version if the cache
// is still fresh (within the check interval). Returns ("", false)
// if the cache is stale or doesn't exist.
func GetCachedResult() (string, bool) {
	entry, err := readCache()
	if err != nil {
		return "", false
	}
	if time.Since(entry.LastCheck) > checkInterval {
		return "", false
	}
	return entry.LatestVersion, true
}

// readCache reads and parses the cache file.
func readCache() (*cacheEntry, error) {
	path, err := cachePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}
