package fsout

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeOutput(t *testing.T, dest, content string) *File {
	t.Helper()
	out, err := Create(dest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.Writer().WriteString(content); err != nil {
		t.Fatal(err)
	}
	return out
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}

func TestCommitCreatesPrivateFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "secret.txt")
	out := writeOutput(t, dest, "plaintext")

	err := out.Commit(false)

	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, err = %v; want 0600", info.Mode().Perm(), err)
	}
	if names := dirEntries(t, dir); len(names) != 1 {
		t.Errorf("leftover files: %v", names)
	}
}

func TestCommitRefusesToOverwriteWithoutPermission(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(dest, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := writeOutput(t, dest, "new")

	err := out.Commit(false)

	if !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}
	if content, _ := os.ReadFile(dest); string(content) != "original" {
		t.Errorf("destination changed to %q", content)
	}
	if names := dirEntries(t, dir); len(names) != 1 {
		t.Errorf("temp file left behind: %v", names)
	}
}

func TestCommitOverwritesWhenAllowed(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(dest, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := writeOutput(t, dest, "new")

	err := out.Commit(true)

	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if content, _ := os.ReadFile(dest); string(content) != "new" {
		t.Errorf("content = %q, want new", content)
	}
}

func TestAbortRemovesTempAndLeavesNoDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.gpg")
	out := writeOutput(t, dest, "partial")

	err := out.Abort()

	if err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if names := dirEntries(t, dir); len(names) != 0 {
		t.Errorf("files left behind: %v", names)
	}
	if err := out.Commit(false); err == nil {
		t.Error("Commit after Abort succeeded")
	}
}

func TestCreateRejectsRelativePath(t *testing.T) {
	if _, err := Create("relative/out.gpg"); err == nil {
		t.Error("relative path accepted")
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	dangling := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "missing"), dangling); err != nil {
		t.Fatal(err)
	}

	missingExists, missingErr := Exists(filepath.Join(dir, "nope"))
	danglingExists, danglingErr := Exists(dangling)

	if missingExists || missingErr != nil {
		t.Errorf("missing file: %v, %v", missingExists, missingErr)
	}
	if !danglingExists || danglingErr != nil {
		t.Errorf("dangling symlink must count as existing: %v, %v", danglingExists, danglingErr)
	}
}
