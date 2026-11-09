package gpg

import (
	"bufio"
	"bytes"
	"strings"
)

const statusPrefix = "[GNUPG:] "

// StatusLine is one machine-readable line from gpg's --status-fd stream.
// See gnupg doc/DETAILS. Args are raw and must be sanitized before display.
type StatusLine struct {
	Keyword string
	Args    []string
}

// ParseStatusLine parses a single status line without its trailing newline.
func ParseStatusLine(line string) (StatusLine, bool) {
	rest, found := strings.CutPrefix(line, statusPrefix)
	if !found {
		return StatusLine{}, false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return StatusLine{}, false
	}
	return StatusLine{Keyword: fields[0], Args: fields[1:]}, true
}

// ParseStatus parses a whole status stream, skipping lines that are not status lines.
func ParseStatus(data []byte) []StatusLine {
	var lines []StatusLine
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), maxStatusLineBytes)
	for scanner.Scan() {
		if line, ok := ParseStatusLine(scanner.Text()); ok {
			lines = append(lines, line)
		}
	}
	return lines
}

// Statuses is the ordered status output of one gpg invocation.
type Statuses []StatusLine

// Has reports whether any line has the given keyword.
func (s Statuses) Has(keyword string) bool {
	_, found := s.First(keyword)
	return found
}

// First returns the first line with the given keyword.
func (s Statuses) First(keyword string) (StatusLine, bool) {
	for _, line := range s {
		if line.Keyword == keyword {
			return line, true
		}
	}
	return StatusLine{}, false
}
