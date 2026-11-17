package ui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/config"
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

func TestReportDecrypt(t *testing.T) {
	result := func(exit int, lines string) gpg.Result {
		return gpg.Result{ExitCode: exit, Status: gpg.ParseStatus([]byte(lines))}
	}
	report := func(r gpg.Result) string {
		var out bytes.Buffer
		New(Startup{Config: config.Default()}, &out).reportDecrypt(context.Background(), r)
		return out.String()
	}

	// A failed decryption without signatures must not claim "Not signed".
	failed := result(2, "[GNUPG:] BADMDC\n[GNUPG:] DECRYPTION_FAILED\n[GNUPG:] END_DECRYPTION\n")
	if got := report(failed); got != "" {
		t.Errorf("failed decryption reported %q, want nothing", got)
	}

	good := result(0, "[GNUPG:] PLAINTEXT 62 0 \n[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 438F68FF5D06DB72 Alice\n[GNUPG:] DECRYPTION_OKAY\n")
	if got := report(good); !strings.Contains(got, "Good signature by Alice") || strings.Contains(got, missingSignerNote) {
		t.Errorf("good signature report = %q", got)
	}

	// A failure that carries signature lines still reports them (e.g. BADSIG).
	bad := result(1, "[GNUPG:] PLAINTEXT 62 0 \n[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 438F68FF5D06DB72 Alice\n")
	if got := report(bad); !strings.Contains(got, "BAD signature") {
		t.Errorf("bad signature report = %q", got)
	}

	unsigned := result(0, "[GNUPG:] PLAINTEXT 62 0 \n[GNUPG:] DECRYPTION_OKAY\n")
	if got := report(unsigned); !strings.Contains(got, "Not signed.") {
		t.Errorf("unsigned report = %q", got)
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
