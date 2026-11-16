package ui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/gpg"
)

func TestOpenFileInputRoutesBySize(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, size int) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const maxBytes = 8

	atCap, err := openFileInput(write("at-cap", maxBytes), maxBytes)
	if err != nil || atCap.large != nil || len(atCap.data) != maxBytes {
		t.Errorf("at cap: large=%v len=%d err=%v, want in memory", atCap.large != nil, len(atCap.data), err)
	}

	overCap, err := openFileInput(write("over-cap", maxBytes+1), maxBytes)
	if err != nil || overCap.large == nil || overCap.data != nil {
		t.Fatalf("over cap: large=%v err=%v, want streamed", overCap.large != nil, err)
	}
	overCap.close()

	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "at-cap"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := openFileInput(link, maxBytes); err == nil {
		t.Error("symlink: want error")
	}
}

func TestResultDestinations(t *testing.T) {
	cases := []struct {
		name                           string
		isText, nextToInput, clipboard bool
		want                           []destination
	}{
		{"text source", true, false, true, []destination{destScreen, destClipboard, destFile, destBack}},
		{"text source, no clipboard", true, false, false, []destination{destScreen, destFile, destBack}},
		{"file source, text result", true, true, true, []destination{destFile, destScreen, destClipboard, destBack}},
		{"file source, binary result", false, true, true, []destination{destFile, destBack}},
		{"text source, binary result", false, false, true, []destination{destFile, destBack}},
	}
	for _, testCase := range cases {
		got := resultDestinations(testCase.isText, testCase.nextToInput, testCase.clipboard)
		if !slices.Equal(got, testCase.want) {
			t.Errorf("%s: %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestDecryptedAcceptsInlineSigned(t *testing.T) {
	status := func(lines string) gpg.Result {
		return gpg.Result{Status: gpg.ParseStatus([]byte(lines))}
	}
	cases := map[string]bool{
		"[GNUPG:] PLAINTEXT 62 0 \n[GNUPG:] END_DECRYPTION\n": true,
		"[GNUPG:] PLAINTEXT 62 0 \n[GNUPG:] GOODSIG ABCD x\n": true, // gpg --sign, no encryption
		"[GNUPG:] NODATA 1\n": false,
	}
	for lines, want := range cases {
		if got := decrypted(status(lines)); got != want {
			t.Errorf("decrypted(%q) = %v, want %v", lines, got, want)
		}
	}
}

func TestOutputDirPrefersPGPDir(t *testing.T) {
	app := &App{}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got := app.outputDir(); got != cwd {
		t.Errorf("unset: %q, want cwd %q", got, cwd)
	}
	app.Config.PGPDir = "/tmp/pgp"
	if got := app.outputDir(); got != "/tmp/pgp" {
		t.Errorf("set: %q, want /tmp/pgp", got)
	}
}
