package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newConfigPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cryptosis")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "config.json")
}

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	path := newConfigPath(t)

	loaded, err := Load(path)

	if err != nil || loaded != Default() {
		t.Errorf("Load = %+v, %v; want defaults", loaded, err)
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	path := newConfigPath(t)
	saved := Default()
	saved.ClipboardClearSeconds = 30
	saved.AllowUnverifiedRecipients = true
	saved.DefaultSigningKey = "BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72"

	if err := Save(path, saved); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)

	if err != nil || loaded != saved {
		t.Errorf("Load = %+v, %v; want %+v", loaded, err, saved)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSaveCreatesPrivateDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "config.json")

	err := Save(path, Default())

	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestLoadAppliesDefaultsForOmittedFields(t *testing.T) {
	path := newConfigPath(t)
	if err := os.WriteFile(path, []byte(`{"armorFiles": true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)

	if err != nil || !loaded.ArmorFiles || loaded.Keyserver != Default().Keyserver {
		t.Errorf("Load = %+v, %v", loaded, err)
	}
}

func TestLoadRejectsBadContent(t *testing.T) {
	tests := map[string]string{
		"unknown field":   `{"skipConfirm": true}`,
		"trailing data":   `{} {}`,
		"http keyserver":  `{"keyserver": "http://keys.openpgp.org"}`,
		"relative gpg":    `{"gpgPath": "bin/gpg"}`,
		"bad expiry":      `{"keyExpiry": "2y; rm"}`,
		"bad algo":        `{"keyAlgo": "rsa1024"}`,
		"short key id":    `{"defaultSigningKey": "5D06DB72"}`,
		"negative clear":  `{"clipboardClearSeconds": -1}`,
		"not json":        `gpgPath=/tmp/evil`,
		"keyserver creds": `{"keyserver": "https://user:pw@keys.example"}`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := newConfigPath(t)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestLoadRejectsUnsafePermissions(t *testing.T) {
	tests := map[string]struct {
		fileMode, dirMode os.FileMode
	}{
		"group-writable file": {0o620, 0o700},
		"world-writable file": {0o602, 0o700},
		"world-writable dir":  {0o600, 0o777},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := newConfigPath(t)
			if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			mustChmod(t, path, tc.fileMode)
			mustChmod(t, filepath.Dir(path), tc.dirMode)

			_, err := Load(path)

			if err == nil || !strings.Contains(err.Error(), "writable") {
				t.Errorf("err = %v, want writable refusal", err)
			}
		})
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	path := newConfigPath(t)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)

	if err == nil {
		t.Error("symlinked config accepted")
	}
}

func TestPathHonoursAbsoluteXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/config")

	path, err := Path()

	if err != nil || path != "/custom/config/cryptosis/config.json" {
		t.Errorf("Path = %q, %v", path, err)
	}
}

func TestPathIgnoresRelativeXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("HOME", "/home/test")

	path, err := Path()

	if err != nil || path != "/home/test/.config/cryptosis/config.json" {
		t.Errorf("Path = %q, %v", path, err)
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
