package dirlist

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	armoredMessage = "-----BEGIN PGP MESSAGE-----\n\nhQEMA\n-----END PGP MESSAGE-----\n"
	armoredSig     = "-----BEGIN PGP SIGNATURE-----\n\niQ\n-----END PGP SIGNATURE-----\n"
	armoredKey     = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n-----END PGP PUBLIC KEY BLOCK-----\n"
)

// writeFile creates name in dir with content and a modification time age ago.
func writeFile(t *testing.T, dir, name, content string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "msg.asc", armoredMessage, 1*time.Hour)
	writeFile(t, dir, "msg.gpg", "\x84\x5e\x03rest", 2*time.Hour)
	writeFile(t, dir, "doc.sig", armoredSig, 3*time.Hour)
	writeFile(t, dir, "key.asc", armoredKey, 4*time.Hour)
	writeFile(t, dir, "signed.gpg", "\xa3\x01data", 5*time.Hour)
	writeFile(t, dir, "notes.txt", "héllo\n", 6*time.Hour)
	writeFile(t, dir, "blob.bin", "\x00\x01\x02", 7*time.Hour)
	text := writeFile(t, dir, ".hidden", "x", 0)
	if err := os.Symlink(text, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"zeta", "alpha", ".git"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	listing, err := List(dir, 100)
	if err != nil {
		t.Fatal(err)
	}

	want := []struct {
		name string
		kind Kind
	}{
		{"alpha", Dir}, {"zeta", Dir},
		{"msg.asc", ArmoredMessage}, {"msg.gpg", BinaryEncrypted}, {"doc.sig", Signature},
		{"key.asc", Key}, {"signed.gpg", OpenPGPOther}, {"notes.txt", Text}, {"blob.bin", Binary},
	}
	if listing.Truncated {
		t.Error("Truncated = true")
	}
	if len(listing.Entries) != len(want) {
		t.Fatalf("got %d entries %+v, want %d", len(listing.Entries), listing.Entries, len(want))
	}
	for i, entry := range listing.Entries {
		if entry.Name != want[i].name || entry.Kind != want[i].kind {
			t.Errorf("entry %d = %s/%v, want %s/%v", i, entry.Name, entry.Kind, want[i].name, want[i].kind)
		}
	}
	notes := listing.Entries[7]
	if notes.Size != int64(len("héllo\n")) || time.Since(notes.Modified) < 5*time.Hour {
		t.Errorf("notes metadata = %+v", notes)
	}
	if runtime.GOOS == "darwin" && notes.Created.IsZero() {
		t.Error("Created is zero on darwin")
	}
}

func TestListTruncatesOldestFiles(t *testing.T) {
	dir := t.TempDir()
	for i, name := range []string{"a", "b", "c", "d", "e"} {
		writeFile(t, dir, name, "x", time.Duration(i)*time.Hour) // a newest
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	listing, err := List(dir, 3)

	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range listing.Entries {
		names = append(names, entry.Name)
	}
	if !listing.Truncated || strings.Join(names, ",") != "sub,a,b,c" {
		t.Errorf("Truncated=%v names=%v, want true and sub,a,b,c", listing.Truncated, names)
	}
}

func TestListUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	dir := t.TempDir()
	path := writeFile(t, dir, "locked", armoredMessage, time.Hour)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}

	listing, err := List(dir, 10)

	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Entries) != 1 || listing.Entries[0].Kind != Unreadable || listing.Entries[0].Modified.IsZero() {
		t.Errorf("entries = %+v, want one Unreadable with a time", listing.Entries)
	}
}

func TestClassifyTextCutMidRune(t *testing.T) {
	head := []byte(strings.Repeat("a", detectBytes-1) + "é")[:detectBytes] // é split by the window
	if got := classify(head, true); got != Text {
		t.Errorf("classify = %v, want Text", got)
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	text := writeFile(t, dir, "plain", "hello", 0)
	link := filepath.Join(dir, "link")
	fifo := filepath.Join(dir, "fifo")
	if err := os.Symlink(text, link); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	if data, err := ReadFile(text, 100); err != nil || string(data) != "hello" {
		t.Errorf("regular: %q, %v", data, err)
	}
	if _, err := ReadFile(text, 4); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("over cap: err = %v", err)
	}
	for _, path := range []string{link, fifo} { // a FIFO must not block
		if _, err := ReadFile(path, 100); !errors.Is(err, errNotRegular) {
			t.Errorf("%s: err = %v, want errNotRegular", filepath.Base(path), err)
		}
	}
}
