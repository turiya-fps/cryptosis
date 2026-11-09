package gpg

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

func TestQuoteArgv(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"safe", []string{"/usr/bin/gpg", "--batch", "--", "/tmp/a.txt"}, "/usr/bin/gpg --batch -- /tmp/a.txt"},
		{"empty", []string{""}, "''"},
		{"space", []string{"/tmp/my file"}, "'/tmp/my file'"},
		{"single quote", []string{"it's"}, `'it'\''s'`},
		{"shell metachars", []string{"$(rm -rf ~);`x`"}, "'$(rm -rf ~);`x`'"},
		{"unicode", []string{"Zoë"}, "'Zoë'"},
		{"control char", []string{"a\x1b[2Jb"}, `$'a\x1b[2Jb'`},
		{"newline and quote", []string{"a\n'b\\"}, `$'a\x0a\'b\\'`},
		{"invalid utf8", []string{"a\xffb"}, `$'a\xffb'`},
		{"bidi override", []string{"x\xe2\x80\xaey"}, `$'x\xe2\x80\xaey'`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := QuoteArgv(tc.argv); got != tc.want {
				t.Errorf("QuoteArgv(%q) = %s, want %s", tc.argv, got, tc.want)
			}
		})
	}
}

// Pasting the preview into a real shell must reproduce the argv byte for byte.
func TestQuoteArgvRoundTripsThroughBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	argv := []string{
		"plain", "", "with space", "it's", "$HOME", "`id`", "a;b|c&d", "*?[x]",
		"tab\there", "nl\nhere", "esc\x1b[0m", "bad\xff\xfe", "x\xe2\x80\xaey", "back\\slash", "Zoë 🔑",
		"\x7f", "trailing\\", "\\x41",
	}
	script := "set -- " + QuoteArgv(argv) + `; for a in "$@"; do printf '%s\0' "$a"; done`
	cmd := exec.Command(bash, "-c", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash: %v: %s", err, stderr.String())
	}

	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(got) != len(argv) {
		t.Fatalf("got %d args, want %d: %q", len(got), len(argv), got)
	}
	for i := range argv {
		if !bytes.Equal([]byte(got[i]), []byte(argv[i])) {
			t.Errorf("arg %d: got %q, want %q", i, got[i], argv[i])
		}
	}
}

func FuzzQuoteArgv(f *testing.F) {
	for _, seed := range []string{"", "a b", "it's", "\x1b[0m", "\xff", "x\xe2\x80\xaey"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, arg string) {
		quoted := QuoteArgv([]string{arg})
		if sanitize.Line(quoted) != quoted {
			t.Fatalf("quoted output not terminal-safe: %q", quoted)
		}
	})
}
