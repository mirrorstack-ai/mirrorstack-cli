// Package credentials reads and writes the CLI's persisted OAuth tokens.
//
// File location is os.UserConfigDir() + "/mirrorstack/credentials.json"
// (~/.config on Linux, ~/Library/Application Support on macOS,
// %APPDATA% on Windows). Mode 0600 — same trust level as ~/.aws/credentials
// and ~/.npmrc.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials is the on-disk shape. Issued by /v1/oauth/token; the CLI
// attaches access_token to every authenticated request and uses
// refresh_token to rotate it via /v1/auth/sessions/refresh once expired.
type Credentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ErrNotFound is returned by Load when no credentials file exists.
// Callers should treat this as "not logged in" rather than a hard error.
var ErrNotFound = errors.New("credentials: not found (run `mirrorstack login`)")

// Path returns the credentials file path. Created lazily by Save.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("credentials: locate config dir: %w", err)
	}
	return filepath.Join(dir, "mirrorstack", "credentials.json"), nil
}

// Save writes creds atomically with mode 0600. Atomic = write to a
// temp file in the same directory, then rename — protects against
// truncated files if the process is killed mid-write.
func Save(c Credentials) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("credentials: create dir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials.*.tmp")
	if err != nil {
		return fmt.Errorf("credentials: temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we error out before the rename. After a
	// successful Rename below the temp is gone and Remove is a no-op.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credentials: chmod: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credentials: encode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("credentials: close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("credentials: rename: %w", err)
	}
	return nil
}

// Load reads the credentials file. Returns ErrNotFound if missing.
func Load() (Credentials, error) {
	path, err := Path()
	if err != nil {
		return Credentials{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Credentials{}, ErrNotFound
		}
		return Credentials{}, fmt.Errorf("credentials: open: %w", err)
	}
	defer f.Close()

	var c Credentials
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return Credentials{}, fmt.Errorf("credentials: decode: %w", err)
	}
	return c, nil
}
