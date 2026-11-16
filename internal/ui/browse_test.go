package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turiya-fps/cryptosis/internal/dirlist"
)

func TestFormatBrowseRow(t *testing.T) {
	columns := browseColumns{name: 20, showCreated: true}
	stamp := time.Date(2026, 11, 14, 10, 21, 0, 0, time.Local)
	entry := func(kind dirlist.Kind) dirlist.Entry {
		return dirlist.Entry{Name: "file", Kind: kind, Size: 4300, Modified: stamp, Created: stamp}
	}
	cases := []struct {
		kind         dirlist.Kind
		mode         browseMode
		marker       string
		wantDisabled bool
	}{
		{dirlist.ArmoredMessage, browseEncrypt, "[encrypted]", false},
		{dirlist.BinaryEncrypted, browseEncrypt, "[encrypted]", false},
		{dirlist.Text, browseEncrypt, "", false},
		{dirlist.Binary, browseEncrypt, "", false},
		{dirlist.Unreadable, browseEncrypt, "✗ unreadable", true},
		{dirlist.ArmoredMessage, browseDecrypt, "", false},
		{dirlist.BinaryEncrypted, browseDecrypt, "", false},
		{dirlist.OpenPGPOther, browseDecrypt, "", false},
		{dirlist.Key, browseDecrypt, "✗ not encrypted", true},
		{dirlist.Binary, browseDecrypt, "✗ not encrypted", true},
		{dirlist.Signature, browseDecrypt, "✗ not encrypted", true},
		{dirlist.Text, browseDecrypt, "✗ not encrypted", true},
		{dirlist.Unreadable, browseDecrypt, "✗ unreadable", true},
	}
	for _, testCase := range cases {
		label, reason := formatBrowseRow(entry(testCase.kind), columns, testCase.mode)
		name := kindLabel(testCase.kind) + "/" + map[browseMode]string{browseEncrypt: "encrypt", browseDecrypt: "decrypt"}[testCase.mode]
		if (reason != "") != testCase.wantDisabled {
			t.Errorf("%s: reason = %q, want disabled=%v", name, reason, testCase.wantDisabled)
		}
		if testCase.marker != "" && !strings.HasSuffix(label, "  "+testCase.marker) {
			t.Errorf("%s: label %q lacks marker %q", name, label, testCase.marker)
		}
		if testCase.marker == "" && (strings.Contains(label, "✗") || strings.Contains(label, "[encrypted]")) {
			t.Errorf("%s: unexpected marker in %q", name, label)
		}
		if !strings.Contains(label, "4.2K") || strings.Count(label, "2026-11-14 10:21") != 2 {
			t.Errorf("%s: metadata missing in %q", name, label)
		}
	}
}

func TestFormatBrowseRowSanitizesAndAligns(t *testing.T) {
	columns := browseColumns{name: 12}
	hostile := dirlist.Entry{Name: "evil\x1b[31m-name-that-is-long", Kind: dirlist.Text, Modified: time.Now()}
	plain := dirlist.Entry{Name: "a", Kind: dirlist.Text, Modified: time.Now()}

	hostileRow, _ := formatBrowseRow(hostile, columns, browseEncrypt)
	plainRow, _ := formatBrowseRow(plain, columns, browseEncrypt)

	if strings.ContainsRune(hostileRow, '\x1b') {
		t.Errorf("escape not stripped: %q", hostileRow)
	}
	typeColumn := func(row string) int { // in runes: "…" is 3 bytes
		before, _, _ := strings.Cut(row, "text")
		return len([]rune(before))
	}
	if typeColumn(hostileRow) != typeColumn(plainRow) {
		t.Errorf("columns misaligned:\n%q\n%q", hostileRow, plainRow)
	}
	if strings.Contains(plainRow, "–") { // created column hidden
		t.Errorf("created column shown: %q", plainRow)
	}
	if !strings.HasSuffix(browseHeader(browseColumns{name: 12, showCreated: true}), "CREATED") {
		t.Error("header lacks CREATED")
	}
}

func TestColumnsForWidth(t *testing.T) {
	cases := []struct {
		width       int
		name        int
		showCreated bool
	}{
		{80, 80 - browseFixedWidth, false}, // 14: full row fits 80 columns
		{60, minNameWidth, false},
		{200, maxNameWidth, true},
		{browseFixedWidth + createdWidth + minNameWidth, minNameWidth, true},
		{browseFixedWidth + createdWidth + minNameWidth - 1, minNameWidth + createdWidth - 1, false},
	}
	for _, testCase := range cases {
		got := columnsForWidth(testCase.width)
		if got.name != testCase.name || got.showCreated != testCase.showCreated {
			t.Errorf("width %d: %+v, want name=%d showCreated=%v", testCase.width, got, testCase.name, testCase.showCreated)
		}
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{0: "0B", 1023: "1023B", 1024: "1.0K", 4300: "4.2K", 512 << 10: "512K", 3 << 20: "3.0M", 5 << 40: "5.0T"}
	for size, want := range cases {
		if got := humanSize(size); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", size, got, want)
		}
	}
}

func TestRejectDisabled(t *testing.T) {
	validate := rejectDisabled(map[string]string{"plain.txt": "Not an encrypted PGP message."})

	if err := validate(browseChoice{browseFile, "plain.txt"}); err == nil || err.Error() != "Not an encrypted PGP message." {
		t.Errorf("disabled file: err = %v", err)
	}
	if err := validate(browseChoice{browseFile, "msg.asc"}); err != nil {
		t.Errorf("enabled file: err = %v", err)
	}
	if err := validate(browseChoice{browseDir, "plain.txt"}); err != nil { // same name, but a directory
		t.Errorf("directory: err = %v", err)
	}
}

func TestParentRel(t *testing.T) {
	cases := map[string][2]string{"a": {"", "a"}, "a/b": {"a", "b"}, "a/b/c": {"a/b", "c"}}
	for rel, want := range cases {
		if parent, child := parentRel(rel); parent != want[0] || child != want[1] {
			t.Errorf("parentRel(%q) = %q, %q; want %q, %q", rel, parent, child, want[0], want[1])
		}
	}
}

func TestBrowseWithoutDirectoryPrintsNote(t *testing.T) {
	app, out, _ := newTestApp(t)

	path, err := app.browsePGPDir(browseDecrypt)

	if path != "" || err != nil {
		t.Errorf("path=%q err=%v, want back with no error", path, err)
	}
	if !strings.Contains(out.String(), "Settings → PGP file directory") {
		t.Errorf("note missing: %q", out.String())
	}
}

func TestValidatePGPDirOrEmpty(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for value, wantOK := range map[string]bool{"": true, " ": true, dir: true, file: false, filepath.Join(dir, "missing"): false} {
		if err := validatePGPDirOrEmpty(value); (err == nil) != wantOK {
			t.Errorf("validatePGPDirOrEmpty(%q) = %v, want ok=%v", value, err, wantOK)
		}
	}
}

func TestAbbreviateHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	cases := map[string]string{home: "~", filepath.Join(home, "pgp"): "~/pgp", home + "x/pgp": home + "x/pgp", "/etc": "/etc"}
	for path, want := range cases {
		if got := abbreviateHome(path); got != want {
			t.Errorf("abbreviateHome(%q) = %q, want %q", path, got, want)
		}
	}
}
