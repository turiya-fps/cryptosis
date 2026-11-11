package gpg

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/gpgtest"
)

func TestSendKeysArgv(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	argv := strings.Join(runner.Argv(SendKeysCommand([]string{"ABCD"}, "https://keys.example")), " ")

	want := "/usr/bin/gpg --batch --status-fd 3 --keyserver https://keys.example --send-keys -- ABCD"
	if argv != want {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestImportKeepUIDArgv(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	argv := strings.Join(runner.Argv(ImportKeepUIDCommand("a@e.org")), " ")

	want := "/usr/bin/gpg --batch --status-fd 3 --import-filter keep-uid=mbox=a@e.org --import"
	if argv != want {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

// TestImportKeepUIDDropsOtherUIDs covers the WKD rule: a key fetched for one
// address must not import that address together with unrelated user IDs.
func TestImportKeepUIDDropsOtherUIDs(t *testing.T) {
	source, sourceHome := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, source.Bin(), sourceHome, "Alice <alice@example.org>")
	if out, err := exec.Command(source.Bin(), "--homedir", sourceHome, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-uid", "--", fpr, "Alice <mallory-lookalike@example.net>").CombinedOutput(); err != nil {
		t.Fatalf("quick-add-uid: %v: %s", err, out)
	}
	exported, err := exec.Command(source.Bin(), "--homedir", sourceHome, "--batch", "--export", "--", fpr).Output()
	if err != nil {
		t.Fatal(err)
	}
	target, _ := newTestRunner(t)

	preview, err := target.Run(context.Background(), ImportPreviewKeepUIDCommand("alice@example.org").WithStdin(bytes.NewReader(exported)))
	if err != nil || !preview.Succeeded() {
		t.Fatalf("preview: err=%v exit=%d stderr=%s", err, preview.ExitCode, preview.Stderr)
	}
	keys, err := ParseKeys(preview.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || len(keys[0].UIDs) != 1 || !strings.Contains(keys[0].UIDs[0].UserID, "alice@example.org") {
		t.Fatalf("preview kept %v, want only alice@example.org", keys[0].UIDs)
	}

	if _, err := target.Run(context.Background(), ImportKeepUIDCommand("alice@example.org").WithStdin(bytes.NewReader(exported))); err != nil {
		t.Fatal(err)
	}
	listing, err := target.Run(context.Background(), ListKeysCommand(false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(listing.Stdout), "mallory-lookalike") {
		t.Fatal("unrelated user ID was imported")
	}
	if !strings.Contains(string(listing.Stdout), "alice@example.org") {
		t.Fatal("wanted user ID missing after import")
	}
}

// importUIDLessFixture returns the exported form of fpr with every user ID
// stripped, as keys.openpgp.org serves for unverified addresses: a keep-uid
// export filter matching nothing leaves the key without user IDs.
func importUIDLessFixture(t *testing.T, bin, home, fpr string) []byte {
	t.Helper()
	stripped, err := exec.Command(bin, "--homedir", home, "--batch", "--export-filter", "keep-uid=mbox=nowhere@nowhere.invalid", "--export", "--", fpr).Output()
	if err != nil {
		t.Fatal(err)
	}
	return stripped
}

// TestImportUIDLessKey covers keys.openpgp.org behaviour: it serves keys with
// every unverified user ID stripped. gpg builds differ: upstream (2.5.24)
// previews nothing and fails the import ("no user ID", exit 2); Debian's
// patched 2.2.27 previews the key without user IDs and skips it as a new key
// (exit 0, IMPORT_RES no_user_id). Either way the keyring must not change.
func TestImportUIDLessKey(t *testing.T) {
	source, sourceHome := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, source.Bin(), sourceHome, "Bob <bob@example.org>")
	exported := importUIDLessFixture(t, source.Bin(), sourceHome, fpr)
	target, _ := newTestRunner(t)

	preview, err := target.Run(context.Background(), ImportPreviewCommand().WithStdin(bytes.NewReader(exported)))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys(preview.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if len(key.UIDs) != 0 {
			t.Fatalf("preview shows user IDs %v for a UID-less key", key.UIDs)
		}
	}

	imported, err := target.Run(context.Background(), ImportCommand().WithStdin(bytes.NewReader(exported)))
	if err != nil {
		t.Fatal(err)
	}
	if imported.ExitCode == 0 {
		if summary, found := ParseImportSummary(imported.Status); !found || summary.NoUserID != 1 {
			t.Fatalf("UID-less import exit 0 without no_user_id skip: %v", imported.Status)
		}
	}
	listEmpty, err := target.Run(context.Background(), ListKeysCommand(false))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(listEmpty.Stdout, []byte(fpr)) {
		t.Fatal("UID-less import changed the keyring")
	}
}
