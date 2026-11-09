package gpg

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

// QuoteArgv renders argv as a POSIX shell command line that, pasted into a
// shell, runs exactly the same command. Output is always safe to print: args
// holding control, invisible or invalid-UTF-8 bytes use $'...' with \xNN escapes.
func QuoteArgv(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = quoteArg(arg)
	}
	return strings.Join(quoted, " ")
}

func quoteArg(arg string) string {
	switch {
	case arg == "":
		return "''"
	case isShellSafe(arg):
		return arg
	case isPrintable(arg):
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	default:
		return ansiCQuote(arg)
	}
}

func isShellSafe(arg string) bool {
	for _, c := range []byte(arg) {
		isAlnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !isAlnum && !strings.ContainsRune("@%+=:,./_-", rune(c)) {
			return false
		}
	}
	return true
}

func isPrintable(arg string) bool {
	if !utf8.ValidString(arg) {
		return false
	}
	for _, r := range arg {
		if sanitize.IsUnsafeRune(r) {
			return false
		}
	}
	return true
}

// ansiCQuote uses bash/zsh $'...' quoting; byte-level escapes keep it exact.
func ansiCQuote(arg string) string {
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(arg); {
		r, size := utf8.DecodeRuneInString(arg[i:])
		isInvalid := r == utf8.RuneError && size <= 1
		switch {
		case isInvalid || sanitize.IsUnsafeRune(r):
			for _, c := range []byte(arg[i : i+max(size, 1)]) {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
		i += max(size, 1)
	}
	b.WriteByte('\'')
	return b.String()
}
