package sanitize

import (
	"testing"
	"unicode/utf8"
)

// Invisible runes are written as UTF-8 byte escapes so the source stays plain ASCII.
const (
	rightToLeftOverride = "\xe2\x80\xae" // U+202E
	leftToRightIsolate  = "\xe2\x81\xa6" // U+2066
	popDirIsolate       = "\xe2\x81\xa9" // U+2069
	zeroWidthSpace      = "\xe2\x80\x8b" // U+200B
	byteOrderMark       = "\xef\xbb\xbf" // U+FEFF
	nextLine            = "\xc2\x85"     // U+0085 (C1)
	controlSeqIntro     = "\xc2\x9b"     // U+009B (C1 CSI)
	replacementChar     = "\xef\xbf\xbd" // U+FFFD
)

func TestLine(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "Alice <alice@example.org>", "Alice <alice@example.org>"},
		{"ansi escape", "evil\x1b[2J\x1b]0;title\x07name", "evil[2J]0;titlename"},
		{"newline removed", "a\nb\r\nc", "abc"},
		{"tab to space", "a\tb", "a b"},
		{"c1 controls", "a" + nextLine + "b" + controlSeqIntro + "c", "abc"},
		{"bidi override", "user" + rightToLeftOverride + "gpj.exe", "usergpj.exe"},
		{"bidi isolate", "a" + leftToRightIsolate + "b" + popDirIsolate + "c", "abc"},
		{"zero width", "a" + zeroWidthSpace + "b" + byteOrderMark + "c", "abc"},
		{"invalid utf8", "a\xffb", "a" + replacementChar + "b"},
		{"truncated utf8", "a\xe2\x82", "a" + replacementChar + replacementChar},
		{"unicode kept", "Zoë 日本 🔑", "Zoë 日本 🔑"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Line(tc.in); got != tc.want {
				t.Errorf("Line(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestText(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"keeps newlines and tabs", "a\n\tb", "a\n\tb"},
		{"keeps crlf", "a\r\nb", "a\r\nb"},
		{"drops bare cr", "safe\rFAKE", "safeFAKE"},
		{"drops escape", "x\x1b[31my", "x[31my"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Text(tc.in); got != tc.want {
				t.Errorf("Text(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func FuzzSanitize(f *testing.F) {
	seeds := []string{"", "plain", "\x1b[0m", "a" + rightToLeftOverride + "b", "\xff\xfe", "a\r\nb"}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		assertSafe(t, "Line", Line(s), false)
		assertSafe(t, "Text", Text(s), true)
		if Line(Line(s)) != Line(s) || Text(Text(s)) != Text(s) {
			t.Fatalf("not idempotent for %q", s)
		}
	})
}

func assertSafe(t *testing.T, name, out string, multiline bool) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("%s: invalid UTF-8 output %q", name, out)
	}
	for i, r := range out {
		isCRLF := r == '\r' && i+1 < len(out) && out[i+1] == '\n'
		isAllowedWhitespace := multiline && (r == '\n' || r == '\t' || isCRLF)
		if IsUnsafeRune(r) && !isAllowedWhitespace {
			t.Fatalf("%s: unsafe rune %U in output %q", name, r, out)
		}
	}
}
