package ui

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

const (
	tableUserIDRunes  = 40
	pickerUserIDRunes = 60
	dateLayout        = "2006-01-02"
)

// keyring is one snapshot of the gpg keyring, cached for the session until a
// command changes it.
type keyring struct {
	keys       []gpg.Key
	hasSecret  map[string]bool
	ownertrust map[string]gpg.Ownertrust // nil unless read from the trustdb
}

func (r *keyring) find(fpr string) (gpg.Key, bool) {
	for _, key := range r.keys {
		if key.Fingerprint == fpr {
			return key, true
		}
	}
	return gpg.Key{}, false
}

// validityNames maps gpg's validity letters (doc/DETAILS, field 2).
var validityNames = map[string]string{
	"o": "unknown (new)",
	"i": "invalid",
	"d": "disabled",
	"r": "revoked",
	"e": "expired",
	"-": "unknown",
	"q": "undefined",
	"n": "not valid",
	"m": "marginal",
	"f": "full",
	"u": "ultimate",
	"w": "well known",
	"s": "special",
}

// ownertrustLetters maps the colon listing's ownertrust letter (field 9).
var ownertrustLetters = map[string]gpg.Ownertrust{
	"q": gpg.OwnertrustUndefined,
	"n": gpg.OwnertrustNever,
	"m": gpg.OwnertrustMarginal,
	"f": gpg.OwnertrustFull,
	"u": gpg.OwnertrustUltimate,
}

var capabilityNames = []struct {
	letter rune
	name   string
}{
	{'S', "sign"},
	{'E', "encrypt"},
	{'C', "certify"},
	{'A', "authenticate"},
}

func describeValidity(letter string) string {
	if name, known := validityNames[letter]; known {
		return name
	}
	return "unknown"
}

func describeExpiry(expires, now time.Time) string {
	if expires.IsZero() {
		return "never"
	}
	if expires.Before(now) {
		return "expired " + expires.Format(dateLayout)
	}
	return expires.Format(dateLayout)
}

// describeCapabilities names a key's own usage flags (lowercase letters; the
// uppercase ones summarize the whole key and are shown on the primary only).
func describeCapabilities(flags string, wholeKey bool) string {
	var names []string
	for _, capability := range capabilityNames {
		letter := unicode.ToLower(capability.letter)
		if wholeKey {
			letter = capability.letter
		}
		if strings.ContainsRune(flags, letter) {
			names = append(names, capability.name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func (r *keyring) describeOwnertrust(key gpg.Key) string {
	if r.ownertrust != nil {
		if trust, found := r.ownertrust[key.Fingerprint]; found {
			return trust.String()
		}
		return "Unknown"
	}
	if trust, found := ownertrustLetters[key.OwnerTrust]; found {
		return trust.String()
	}
	return "Unknown"
}

// primaryUserID returns the key's first user ID, sanitized for display.
func primaryUserID(key gpg.Key) string {
	if len(key.UIDs) == 0 {
		return "(no user ID)"
	}
	return sanitize.Line(key.UIDs[0].UserID)
}

// groupFingerprint splits a fingerprint into blocks of four for reading aloud.
func groupFingerprint(fpr string) string {
	var blocks []string
	for start := 0; start < len(fpr); start += 4 {
		blocks = append(blocks, fpr[start:min(start+4, len(fpr))])
	}
	return strings.Join(blocks, " ")
}

// truncateRunes shortens s to at most limit runes, marking the cut.
func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit-1]) + "…"
}

// keyPickerLabel is one line in the key picker: user ID and long key ID.
func keyPickerLabel(key gpg.Key, hasSecret bool) string {
	label := truncateRunes(primaryUserID(key), pickerUserIDRunes) + "  " + key.KeyID
	if hasSecret {
		label += "  [secret]"
	}
	return label
}

func renderKeyTable(w io.Writer, ring *keyring, now time.Time) {
	if len(ring.keys) == 0 {
		fmt.Fprintln(w, "No keys in the keyring.")
		return
	}
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "\tUSER ID\tKEY ID\tALGO\tVALIDITY\tEXPIRES\tUSE")
	for _, key := range ring.keys {
		secretMarker := ""
		if ring.hasSecret[key.Fingerprint] {
			secretMarker = "sec"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			secretMarker,
			truncateRunes(primaryUserID(key), tableUserIDRunes),
			key.KeyID,
			sanitize.Line(key.AlgoName()),
			describeValidity(key.Validity),
			describeExpiry(key.Expires, now),
			describeCapabilities(key.Capabilities, true),
		)
	}
	_ = table.Flush()
	fmt.Fprintln(w)
}

func renderKeyDetail(w io.Writer, ring *keyring, key gpg.Key, now time.Time) {
	fmt.Fprintf(w, "\nFingerprint:  %s\n", groupFingerprint(key.Fingerprint))
	for _, uid := range key.UIDs {
		fmt.Fprintf(w, "User ID:      %s  [%s]\n", sanitize.Line(uid.UserID), describeValidity(uid.Validity))
	}
	if ring.hasSecret[key.Fingerprint] {
		fmt.Fprintln(w, "Secret key:   present")
	} else {
		fmt.Fprintln(w, "Secret key:   not present (public key only)")
	}
	fmt.Fprintf(w, "Validity:     %s\n", describeValidity(key.Validity))
	fmt.Fprintf(w, "Owner trust:  %s\n", ring.describeOwnertrust(key))
	fmt.Fprintf(w, "Primary key:  %s, created %s, expires %s, %s\n",
		sanitize.Line(key.AlgoName()), key.Created.Format(dateLayout), describeExpiry(key.Expires, now),
		describeCapabilities(key.Capabilities, false))
	for _, subkey := range key.Subkeys {
		fmt.Fprintf(w, "Subkey:       %s, created %s, expires %s, %s [%s]\n",
			sanitize.Line(subkey.AlgoName()), subkey.Created.Format(dateLayout), describeExpiry(subkey.Expires, now),
			describeCapabilities(subkey.Capabilities, false), describeValidity(subkey.Validity))
		fmt.Fprintf(w, "              %s\n", groupFingerprint(subkey.Fingerprint))
	}
	fmt.Fprintln(w)
}
