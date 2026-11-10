// Package gpgtest provides isolated gpg home directories and test keys for
// integration tests against the real gpg binary.
package gpgtest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Binary returns the absolute path of gpg, skipping the test when gpg is absent.
func Binary(t testing.TB) string {
	t.Helper()
	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatalf("resolve gpg path: %v", err)
	}
	return abs
}

// NewHome creates an empty gpg home directory and stops its agent on cleanup.
// It lives under /tmp because agent socket paths are limited to ~100 bytes,
// which t.TempDir on macOS easily exceeds.
func NewHome(t testing.TB, bin string) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "cgt") //nolint:usetesting // see doc comment: short path needed for sockets
	if err != nil {
		t.Fatalf("create gpg home: %v", err)
	}
	// Loopback lets fixtures create passphrase-less keys without a pinentry;
	// the fake pinentry covers tests that drive cryptosis's Runner (which never
	// passes --pinentry-mode), e.g. key generation without a passphrase.
	conf := "allow-loopback-pinentry\npinentry-program " + writeFakePinentry(t) + "\n"
	if err := os.WriteFile(filepath.Join(home, "gpg-agent.conf"), []byte(conf), 0o600); err != nil {
		t.Fatalf("write gpg-agent.conf: %v", err)
	}
	t.Cleanup(func() {
		gpgconf := filepath.Join(filepath.Dir(bin), "gpgconf")
		_ = exec.Command(gpgconf, "--homedir", home, "--kill", "all").Run() //nolint:gosec // G204: test helper
		_ = os.RemoveAll(home)
	})
	return home
}

// writeFakePinentry installs an assuan pinentry that succeeds every prompt
// with an empty secret, so passphrase-less key generation and use work in
// headless tests through the real gpg-agent path.
func writeFakePinentry(t testing.TB) string {
	t.Helper()
	script := `#!/bin/sh
# Minimal assuan pinentry: greet first (the agent waits for it), then OK every
# request; GETPIN with no data line yields an empty passphrase, CONFIRM accepts.
printf 'OK fake pinentry\n'
while IFS= read -r line; do
  case "$line" in
    BYE*) printf 'OK\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`
	path := filepath.Join(t.TempDir(), "fake-pinentry")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // G306: gpg-agent must execute it
		t.Fatalf("write fake pinentry: %v", err)
	}
	return path
}

// GenerateKey creates a passphrase-less key for uid and returns its fingerprint.
func GenerateKey(t testing.TB, bin, home, uid string) string {
	t.Helper()
	cmd := exec.Command(bin, "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", //nolint:gosec // G204: test helper
		"--status-fd", "1", "--quick-generate-key", uid, "future-default", "default", "2y")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("generate key: %v: %s", err, stderr.String())
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		isKeyCreated := len(fields) == 4 && fields[0] == "[GNUPG:]" && fields[1] == "KEY_CREATED"
		if isKeyCreated {
			return fields[3]
		}
	}
	t.Fatalf("generate key: no KEY_CREATED status in %q", out)
	return ""
}
