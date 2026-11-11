package keyserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/turiya-fps/cryptosis/internal/fetch"
)

// SearchResult is one key from an HKP search listing.
type SearchResult struct {
	Fingerprint string   // full fingerprint when the server sent it, else the key ID
	AlgoID      int      // gpg public-key algorithm ID
	Bits        int      // key size in bits
	Created     int64    // unix time, 0 unknown
	Expires     int64    // unix time, 0 never
	Revoked     bool     // r flag
	Expired     bool     // e flag
	Disabled    bool     // d flag
	UIDs        []string // raw (escaped-decoded) user IDs
}

// Search lists keys matching term (email, name or key ID) via HKP op=index
// in machine-readable form, with fingerprints on.
func (c *Client) Search(ctx context.Context, term string) ([]SearchResult, error) {
	lookup := *c.base
	lookup.Path += "/pks/lookup"
	q := url.Values{}
	q.Set("op", "index")
	q.Set("options", "mr")
	q.Set("fingerprint", "on")
	q.Set("search", term)
	lookup.RawQuery = q.Encode()
	data, err := c.fetch.Get(ctx, lookup.String())
	if err != nil {
		// HKP: 404 = no matching keys; 501 = op=index not implemented.
		var status *fetch.StatusError
		if errors.As(err, &status) {
			switch status.Code {
			case http.StatusNotFound:
				return nil, ErrNotFound
			case http.StatusNotImplemented:
				return nil, ErrNoSearch
			case http.StatusBadRequest:
				return nil, ErrExactSearchOnly
			}
		}
		return nil, err
	}
	results, err := ParseIndex(data)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	return results, nil
}

// ParseIndex reads an HKP machine-readable index listing:
//
//	info:1:1
//	pub:<fpr>:<algo>:<bits>:<created>:<expires>:<flags>
//	uid:<escaped uid>:<created>:<expires>:<flags>
//
// Only pub and uid lines are read; a uid line belongs to the preceding pub
// line. uid text is %XX-decoded; colons inside UIDs arrive escaped.
func ParseIndex(data []byte) ([]SearchResult, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var results []SearchResult
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "pub:"):
			result, err := parsePubLine(line)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		case strings.HasPrefix(line, "uid:"):
			if len(results) == 0 {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) < 2 {
				continue
			}
			results[len(results)-1].UIDs = append(results[len(results)-1].UIDs, decodeMrString(fields[1]))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func parsePubLine(line string) (SearchResult, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return SearchResult{}, fmt.Errorf("malformed pub line %q", line)
	}
	result := SearchResult{Fingerprint: strings.ToUpper(fields[1])}
	result.AlgoID, _ = strconv.Atoi(fields[2])
	result.Bits, _ = strconv.Atoi(fields[3])
	result.Created, _ = strconv.ParseInt(fields[4], 10, 64)
	result.Expires, _ = strconv.ParseInt(fields[5], 10, 64)
	for _, flag := range fields[6] {
		switch flag {
		case 'r':
			result.Revoked = true
		case 'e':
			result.Expired = true
		case 'd':
			result.Disabled = true
		}
	}
	return result, nil
}

// decodeMrString undoes the %XX escaping of the machine-readable format.
func decodeMrString(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if value, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(value))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}
