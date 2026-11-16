package ui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
