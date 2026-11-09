package gpg

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/gpgtest"
)

func newTestRunner(t *testing.T) (*Runner, string) {
	t.Helper()
	bin := gpgtest.Binary(t)
	home := gpgtest.NewHome(t, bin)
	runner, err := NewRunner(bin, home)
	if err != nil {
		t.Fatal(err)
	}
	return runner, home
}

func TestArgvPutsFixedOptionsFirstAndOperandsAfterDoubleDash(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg", homedir: "/tmp/home"}
	command := Command{options: []string{"--list-keys"}, operands: []string{"--delete-secret-keys"}}

	argv := runner.Argv(command)

	want := "/usr/bin/gpg --batch --status-fd 3 --homedir /tmp/home --list-keys -- --delete-secret-keys"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestArgvOmitsDoubleDashWithoutOperands(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	argv := runner.Argv(VersionCommand())

	if got := strings.Join(argv, " "); got != "/usr/bin/gpg --batch --status-fd 3 --version" {
		t.Errorf("argv = %q", got)
	}
}

func TestNewRunnerRejectsRelativeOrMissingBinary(t *testing.T) {
	for _, bin := range []string{"gpg", "./gpg", "/nonexistent/gpg", "/tmp"} {
		if _, err := NewRunner(bin, ""); err == nil {
			t.Errorf("NewRunner(%q) accepted", bin)
		}
	}
}

func TestProbeDetectsSupportedVersion(t *testing.T) {
	runner, _ := newTestRunner(t)

	info, err := runner.Probe(context.Background())

	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !info.Version.AtLeast(MinVersion) {
		t.Errorf("version %v below minimum", info.Version)
	}
}

func TestRunListsGeneratedKey(t *testing.T) {
	runner, home := newTestRunner(t)
	fingerprint := gpgtest.GenerateKey(t, runner.Bin(), home, "Test User <test@example.org>")

	listing, err := runner.Run(context.Background(), ListKeysCommand(true))
	if err != nil || !listing.Succeeded() {
		t.Fatalf("list: err=%v exit=%d stderr=%s", err, listing.ExitCode, listing.Stderr)
	}
	keys, err := ParseKeys(listing.Stdout)

	if err != nil {
		t.Fatalf("ParseKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != fingerprint || len(keys[0].Subkeys) != 1 {
		t.Errorf("keys = %+v, want one key %s with one subkey", keys, fingerprint)
	}
}

func TestRunFeedsStdinAndCollectsStatus(t *testing.T) {
	source, sourceHome := newTestRunner(t)
	fingerprint := gpgtest.GenerateKey(t, source.Bin(), sourceHome, "Exported <exp@example.org>")
	exported := exportPublicKey(t, source.Bin(), sourceHome, fingerprint)
	target, _ := newTestRunner(t)
	importCommand := Command{label: "test import", options: []string{"--import"}}.WithStdin(bytes.NewReader(exported))

	imported, err := target.Run(context.Background(), importCommand)

	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !imported.Succeeded("IMPORT_OK", "IMPORT_RES") {
		t.Errorf("import: exit=%d status=%+v stderr=%s", imported.ExitCode, imported.Status, imported.Stderr)
	}
}

// Streams larger than a pipe buffer must not deadlock stdin, stdout, or status.
func TestRunHandlesLargeStreams(t *testing.T) {
	runner, _ := newTestRunner(t)
	input := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	var armored bytes.Buffer
	enarmor := Command{label: "test enarmor", options: []string{"--enarmor"}}.WithStdin(bytes.NewReader(input)).WithStdout(&armored)

	result, err := runner.Run(context.Background(), enarmor)

	if err != nil || result.ExitCode != 0 {
		t.Fatalf("enarmor: err=%v exit=%d stderr=%s", err, result.ExitCode, result.Stderr)
	}
	if armored.Len() < len(input) || !strings.Contains(armored.String(), "-----END PGP ARMORED FILE-----") {
		t.Errorf("armored output: %d bytes", armored.Len())
	}
}

func TestRunReportsNonZeroExitWithoutError(t *testing.T) {
	runner, _ := newTestRunner(t)
	missingKey := Command{label: "test missing", options: []string{"--list-keys"}, operands: []string{"nobody@invalid.example"}}

	result, err := runner.Run(context.Background(), missingKey)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode == 0 || result.Succeeded() {
		t.Errorf("exit = %d, want non-zero", result.ExitCode)
	}
}

func TestCappedBufferRejectsOverflow(t *testing.T) {
	buffer := &cappedBuffer{limit: 4}

	_, firstErr := buffer.Write([]byte("abc"))
	_, overflowErr := buffer.Write([]byte("de"))

	if firstErr != nil || !errors.Is(overflowErr, ErrOutputTooLarge) || string(buffer.Bytes()) != "abc" {
		t.Errorf("first=%v overflow=%v buf=%q", firstErr, overflowErr, buffer.Bytes())
	}
}

func exportPublicKey(t *testing.T, bin, home, fingerprint string) []byte {
	t.Helper()
	out, err := exec.Command(bin, "--homedir", home, "--batch", "--export", "--", fingerprint).Output()
	if err != nil || len(out) == 0 {
		t.Fatalf("export: %v", err)
	}
	return out
}
