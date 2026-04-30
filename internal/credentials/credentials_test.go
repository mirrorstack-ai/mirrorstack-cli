package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// withTempConfigDir redirects os.UserConfigDir() to a t.TempDir() for the
// duration of the test. Uses the same env var the os package consults
// per platform.
func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", dir)
		return filepath.Join(dir, "Library", "Application Support")
	case "windows":
		t.Setenv("APPDATA", dir)
		return dir
	default:
		t.Setenv("XDG_CONFIG_HOME", dir)
		return dir
	}
}

func TestSaveLoad_Roundtrip(t *testing.T) {
	withTempConfigDir(t)

	want := Credentials{
		AccessToken:  "AT",
		RefreshToken: "RT",
		ExpiresAt:    time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second),
	}
	if err := Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Errorf("tokens mismatch:\n got %+v\nwant %+v", got, want)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}

func TestLoad_NotFound(t *testing.T) {
	withTempConfigDir(t)

	_, err := Load()
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestSave_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes don't map cleanly on Windows")
	}
	withTempConfigDir(t)

	if err := Save(Credentials{AccessToken: "AT"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
}

func TestSave_Atomic_NoTempLeftBehind(t *testing.T) {
	withTempConfigDir(t)

	if err := Save(Credentials{AccessToken: "AT"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path, _ := Path()
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("unexpected file in config dir: %s", e.Name())
		}
	}
}
