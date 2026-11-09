// Package config loads and saves cryptosis settings as JSON.
//
// The file can change what gpg command cryptosis builds (e.g. which gpg binary
// runs), so it is refused unless it is a regular file owned by the current
// user and not writable by group or others, in a directory with the same
// restrictions.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/turiya-fps/cryptosis/internal/fsout"
	"github.com/turiya-fps/cryptosis/internal/gpg"
)

const (
	maxFileBytes          = 64 << 10
	maxClipboardClearSecs = 3600
	dirName               = "cryptosis"
	fileName              = "config.json"
)

// Key algorithms passed to gpg --quick-generate-key; both create a primary
// signing key plus an encryption subkey.
const (
	KeyAlgoFutureDefault = "future-default"
	KeyAlgoDefault       = "default"
)

// Config holds user settings. Command preview/confirmation and --batch are
// deliberately not configurable.
type Config struct {
	GPGPath                   string `json:"gpgPath,omitempty"`
	Keyserver                 string `json:"keyserver"`
	ClipboardClearSeconds     int    `json:"clipboardClearSeconds"`
	KeyAlgo                   string `json:"keyAlgo"`
	KeyExpiry                 string `json:"keyExpiry"`
	DefaultSigningKey         string `json:"defaultSigningKey,omitempty"`
	ArmorFiles                bool   `json:"armorFiles"`
	AccessibleMode            bool   `json:"accessibleMode"`
	AllowUnverifiedRecipients bool   `json:"allowUnverifiedRecipients"`
}

// Default returns the built-in settings.
func Default() Config {
	return Config{
		Keyserver: "https://keys.openpgp.org",
		KeyAlgo:   KeyAlgoFutureDefault,
		KeyExpiry: "2y",
	}
}

// keyExpiryPattern accepts gpg's relative expiry forms, e.g. "2y", "18m", "never".
var keyExpiryPattern = regexp.MustCompile(`^(never|[1-9][0-9]{0,3}[dwmy])$`)

// Validate checks every field; the first problem is returned.
func (c Config) Validate() error {
	if c.GPGPath != "" && !filepath.IsAbs(c.GPGPath) {
		return fmt.Errorf("gpgPath must be an absolute path: %q", c.GPGPath)
	}
	if err := validateKeyserver(c.Keyserver); err != nil {
		return err
	}
	if c.ClipboardClearSeconds < 0 || c.ClipboardClearSeconds > maxClipboardClearSecs {
		return fmt.Errorf("clipboardClearSeconds must be 0 (off) to %d", maxClipboardClearSecs)
	}
	if c.KeyAlgo != KeyAlgoFutureDefault && c.KeyAlgo != KeyAlgoDefault {
		return fmt.Errorf("keyAlgo must be %q or %q", KeyAlgoFutureDefault, KeyAlgoDefault)
	}
	if !keyExpiryPattern.MatchString(c.KeyExpiry) {
		return fmt.Errorf("keyExpiry must look like 2y, 18m, 6w, 30d or never: %q", c.KeyExpiry)
	}
	if c.DefaultSigningKey != "" && !gpg.IsFingerprint(c.DefaultSigningKey) {
		return fmt.Errorf("defaultSigningKey must be a full upper-case fingerprint: %q", c.DefaultSigningKey)
	}
	return nil
}

func validateKeyserver(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("keyserver: %w", err)
	}
	isPlainHTTPSURL := parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == ""
	if !isPlainHTTPSURL {
		return fmt.Errorf("keyserver must be an https:// URL without credentials, query or fragment: %q", raw)
	}
	return nil
}

// Path returns $XDG_CONFIG_HOME/cryptosis/config.json, or ~/.config/... when
// XDG_CONFIG_HOME is unset or relative (per the XDG spec), on Linux and macOS alike.
func Path() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, dirName, fileName), nil
}

// Load reads path, returning defaults when the file does not exist.
func Load(path string) (Config, error) {
	data, err := readTrustedFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	loaded, err := decode(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return loaded, nil
}

func decode(data []byte) (Config, error) {
	loaded := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&loaded); err != nil {
		return Config{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, errors.New("unexpected data after JSON object")
	}
	return loaded, loaded.Validate()
}

func readTrustedFile(path string) ([]byte, error) {
	if err := checkTrusted(filepath.Dir(path), true); err != nil {
		return nil, err
	}
	if err := checkTrusted(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // G304: path checked by checkTrusted
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxFileBytes)
	}
	return data, nil
}

// checkTrusted refuses symlinks, wrong file types, foreign owners and
// group/world-writable modes.
func checkTrusted(path string, wantDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: not a directory (symlinks are refused)", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file (symlinks are refused)", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others (mode %v); run chmod go-w", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s: not owned by the current user", path)
	}
	return nil
}

// Save validates c and atomically writes it to path with mode 0600, creating
// the directory with mode 0700.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := checkTrusted(dir, true); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomically(path, append(data, '\n'))
}

func writeAtomically(path string, data []byte) error {
	out, err := fsout.Create(path)
	if err != nil {
		return err
	}
	if _, err := out.Writer().Write(data); err != nil {
		return errors.Join(err, out.Abort())
	}
	return out.Commit(true)
}
