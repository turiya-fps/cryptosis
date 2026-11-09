package gpg

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxConfigFileBytes = 1 << 20

// ConfigWarning is a gpg.conf setting that can silently change what a
// cryptosis-built command does.
type ConfigWarning struct {
	File   string
	Option string
	Risk   string
}

type riskyOption struct {
	risk string
	// applies reports whether the option's value is risky; nil means always.
	applies func(value string) bool
}

var riskyOptions = map[string]riskyOption{
	"trust-model":               {risk: "encrypts to keys without checking their validity", applies: hasWord("always")},
	"always-trust":              {risk: "encrypts to keys without checking their validity"},
	"encrypt-to":                {risk: "every encryption also includes this key"},
	"hidden-encrypt-to":         {risk: "every encryption also includes this key, hidden"},
	"default-recipient":         {risk: "may add a recipient you did not choose"},
	"default-recipient-self":    {risk: "may add a recipient you did not choose"},
	"pinentry-mode":             {risk: "passphrases may be requested outside pinentry", applies: hasWord("loopback")},
	"auto-key-retrieve":         {risk: "verifying may contact keyservers (reveals which keys you check)"},
	"auto-key-import":           {risk: "verifying may import keys embedded in signatures"},
	"keyserver-options":         {risk: "verifying may contact keyservers (reveals which keys you check)", applies: hasWord("auto-key-retrieve")},
	"ignore-mdc-error":          {risk: "accepts messages without integrity protection"},
	"allow-weak-digest-algos":   {risk: "accepts signatures made with broken hash algorithms"},
	"allow-weak-key-signatures": {risk: "accepts key signatures made with SHA-1"},
	"use-embedded-filename":     {risk: "decryption may write to a file name chosen by the sender"},
}

func hasWord(word string) func(string) bool {
	return func(value string) bool {
		for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
			if strings.EqualFold(strings.Trim(field, `"`), word) {
				return true
			}
		}
		return false
	}
}

// ScanConfig returns risky settings in one gpg.conf-format file. Later lines
// override earlier ones, and "no-<option>" cancels <option>.
func ScanConfig(r io.Reader, fileName string) ([]ConfigWarning, error) {
	active := map[string]ConfigWarning{}
	var order []string

	scanner := bufio.NewScanner(io.LimitReader(r, maxConfigFileBytes))
	for scanner.Scan() {
		option, value, isOption := parseConfigLine(scanner.Text())
		if !isOption {
			continue
		}
		if negated, found := strings.CutPrefix(option, "no-"); found {
			delete(active, negated)
			continue
		}
		risky, known := riskyOptions[option]
		if !known {
			continue
		}
		if risky.applies != nil && !risky.applies(value) {
			delete(active, option)
			continue
		}
		if _, seen := active[option]; !seen {
			order = append(order, option)
		}
		active[option] = ConfigWarning{File: fileName, Option: strings.TrimSpace(option + " " + value), Risk: risky.risk}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", fileName, err)
	}

	var warnings []ConfigWarning
	for _, option := range order {
		if warning, stillActive := active[option]; stillActive {
			warnings = append(warnings, warning)
		}
	}
	return warnings, nil
}

// parseConfigLine skips blanks, comments and [meta] lines; leading dashes are tolerated.
func parseConfigLine(line string) (option, value string, isOption bool) {
	line = strings.TrimSpace(line)
	isSkipped := line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[")
	if isSkipped {
		return "", "", false
	}
	option, value, _ = strings.Cut(line, " ")
	option, _, _ = strings.Cut(option, "\t")
	return strings.ToLower(strings.TrimLeft(option, "-")), strings.TrimSpace(value), true
}

// ConfigWarnings scans the config files this gpg reads: the system gpg.conf,
// then the user's first existing gpg.conf-<version> variant or gpg.conf
// (libgpg-error argparse.c, try_versioned_conffile).
func (r *Runner) ConfigWarnings(ctx context.Context, version Version) ([]ConfigWarning, error) {
	dirs, err := r.gpgconfDirs(ctx)
	if err != nil {
		return nil, err
	}
	homedir := dirs["homedir"]
	if r.homedir != "" {
		homedir = r.homedir
	}

	files := []string{filepath.Join(dirs["sysconfdir"], "gpg.conf"), userConfigFile(homedir, version)}
	var warnings []ConfigWarning
	for _, file := range files {
		fileWarnings, err := scanConfigFile(file)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, fileWarnings...)
	}
	return warnings, nil
}

func userConfigFile(homedir string, version Version) string {
	base := filepath.Join(homedir, "gpg.conf")
	candidates := []string{
		fmt.Sprintf("%s-%d.%d.%d", base, version.Major, version.Minor, version.Patch),
		fmt.Sprintf("%s-%d.%d", base, version.Major, version.Minor),
		fmt.Sprintf("%s-%d", base, version.Major),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return base
}

func scanConfigFile(path string) ([]ConfigWarning, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path derived from gpgconf directories
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ScanConfig(f, path)
}

// gpgconfDirs runs the gpgconf installed next to gpg, avoiding a PATH lookup.
func (r *Runner) gpgconfDirs(ctx context.Context) (map[string]string, error) {
	gpgconf := filepath.Join(filepath.Dir(r.bin), "gpgconf")
	cmd := exec.CommandContext(ctx, gpgconf, "--list-dirs") //nolint:gosec // G204: fixed arguments, binary beside gpg
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gpgconf --list-dirs: %w", err)
	}
	return parseGpgconfDirs(out)
}

// parseGpgconfDirs reads "name:value" lines; values are percent-escaped.
func parseGpgconfDirs(out []byte) (map[string]string, error) {
	dirs := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		name, escaped, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		value, err := url.PathUnescape(escaped)
		if err != nil {
			return nil, fmt.Errorf("gpgconf --list-dirs: bad value for %s: %w", name, err)
		}
		dirs[name] = value
	}
	if dirs["homedir"] == "" || dirs["sysconfdir"] == "" {
		return nil, errors.New("gpgconf --list-dirs: homedir or sysconfdir missing")
	}
	return dirs, nil
}
