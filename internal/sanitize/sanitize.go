// Package sanitize makes untrusted text safe to print to a terminal.
//
// Untrusted text includes user IDs, keyserver data and decrypted or verified
// plaintext. Control characters (C0, DEL, C1), Unicode bidi controls and
// invisible format characters are removed, so they cannot inject terminal escape
// sequences or visually reorder text. Invalid UTF-8 becomes U+FFFD.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// Line returns s as a single safe line. Tabs become spaces and every other
// control character, including newlines, is removed.
func Line(s string) string {
	return clean(s, false)
}

// Text returns s as safe multi-line text. Newlines and tabs are kept; a CR is
// kept only when it is part of a CRLF pair.
func Text(s string) string {
	return clean(s, true)
}

func clean(s string, multiline bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			b.WriteRune(utf8.RuneError)
			i += max(size, 1)
			continue
		}
		switch {
		case r == '\t' && multiline:
			b.WriteByte('\t')
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n' && multiline:
			b.WriteByte('\n')
		case r == '\r' && multiline && i+1 < len(s) && s[i+1] == '\n':
			b.WriteByte('\r')
		case IsUnsafeRune(r):
			// dropped
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// IsUnsafeRune reports whether r is a control or invisible formatting rune.
func IsUnsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f: // C0, DEL, C1
		return true
	case r == 0x061c, // Arabic letter mark
		r >= 0x200b && r <= 0x200f, // zero-width chars, LRM, RLM
		r >= 0x2028 && r <= 0x202e, // line/para separators, bidi embeddings/overrides
		r >= 0x2060 && r <= 0x206f, // word joiner, bidi isolates, deprecated format chars
		r == 0xfeff,                // BOM / zero-width no-break space
		r >= 0xfff9 && r <= 0xfffb: // interlinear annotation
		return true
	}
	return false
}
