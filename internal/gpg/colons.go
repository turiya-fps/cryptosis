package gpg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Colon listing field positions (0-based), from gnupg doc/DETAILS.
const (
	fieldType = iota
	fieldValidity
	fieldKeyLength
	fieldAlgo
	fieldKeyID
	fieldCreated
	fieldExpires
	_ // certificate S/N, UID hash, trust signature info
	fieldOwnerTrust
	fieldUserID // also holds the fingerprint on fpr records
	_           // signature class
	fieldCapabilities
	_ // issuer certificate fingerprint
	_ // flag field
	_ // S/N of a token
	_ // hash algorithm
	fieldCurve
)

// ErrMalformedListing is returned when a colon listing breaks gpg's documented structure.
var ErrMalformedListing = errors.New("malformed gpg key listing")

// KeyMaterial holds the fields shared by primary keys and subkeys.
type KeyMaterial struct {
	Fingerprint  string
	KeyID        string
	Validity     string
	Algo         int
	Length       int
	Curve        string
	Created      time.Time
	Expires      time.Time // zero when the key does not expire
	Capabilities string
}

// AlgoName returns a readable name for Algo, tolerating unknown algorithm IDs.
func (k KeyMaterial) AlgoName() string {
	name, known := pubkeyAlgoNames[k.Algo]
	switch {
	case k.Curve != "":
		return k.Curve
	case known && strings.HasPrefix(name, "RSA"):
		return fmt.Sprintf("%s %d", name, k.Length)
	case known:
		return name
	default:
		return fmt.Sprintf("algo %d", k.Algo)
	}
}

// UID is a user ID. UserID is unescaped but untrusted: sanitize before display.
type UID struct {
	Validity string
	UserID   string
}

// Key is a primary key with its user IDs and subkeys.
type Key struct {
	KeyMaterial
	Secret     bool
	OwnerTrust string
	UIDs       []UID
	Subkeys    []KeyMaterial
}

// OpenPGP public-key algorithm IDs (RFC 9580 section 9.1, plus legacy IDs).
var pubkeyAlgoNames = map[int]string{
	1:  "RSA",
	2:  "RSA (encrypt only)",
	3:  "RSA (sign only)",
	16: "Elgamal",
	17: "DSA",
	18: "ECDH",
	19: "ECDSA",
	22: "EdDSA",
	25: "X25519",
	26: "X448",
	27: "Ed25519",
	28: "Ed448",
}

// ParseKeys parses `--with-colons --with-fingerprint` output of --list-keys or
// --list-secret-keys. Unknown record types are ignored.
func ParseKeys(data []byte) ([]Key, error) {
	var keys []Key
	var current *KeyMaterial // record that the next fpr line belongs to

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), maxColonLineBytes)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		switch fields[fieldType] {
		case "pub", "sec":
			key := Key{
				KeyMaterial: parseKeyMaterial(fields),
				Secret:      fields[fieldType] == "sec",
				OwnerTrust:  field(fields, fieldOwnerTrust),
			}
			keys = append(keys, key)
			current = &keys[len(keys)-1].KeyMaterial
		case "sub", "ssb":
			if len(keys) == 0 {
				return nil, fmt.Errorf("%w: subkey before primary key", ErrMalformedListing)
			}
			primary := &keys[len(keys)-1]
			primary.Subkeys = append(primary.Subkeys, parseKeyMaterial(fields))
			current = &primary.Subkeys[len(primary.Subkeys)-1]
		case "uid":
			if len(keys) == 0 {
				return nil, fmt.Errorf("%w: user ID before primary key", ErrMalformedListing)
			}
			uid := UID{Validity: field(fields, fieldValidity), UserID: unescapeColonField(field(fields, fieldUserID))}
			keys[len(keys)-1].UIDs = append(keys[len(keys)-1].UIDs, uid)
			current = nil
		case "fpr":
			if err := assignFingerprint(current, field(fields, fieldUserID)); err != nil {
				return nil, err
			}
			current = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedListing, err)
	}
	return keys, validateFingerprints(keys)
}

func assignFingerprint(target *KeyMaterial, fingerprint string) error {
	if target == nil {
		return nil // fpr lines may also follow records we ignore
	}
	if !IsFingerprint(fingerprint) {
		return fmt.Errorf("%w: invalid fingerprint %q", ErrMalformedListing, fingerprint)
	}
	target.Fingerprint = fingerprint
	return nil
}

func validateFingerprints(keys []Key) error {
	for _, key := range keys {
		if key.Fingerprint == "" {
			return fmt.Errorf("%w: key %s has no fingerprint", ErrMalformedListing, key.KeyID)
		}
		for _, sub := range key.Subkeys {
			if sub.Fingerprint == "" {
				return fmt.Errorf("%w: subkey %s has no fingerprint", ErrMalformedListing, sub.KeyID)
			}
		}
	}
	return nil
}

func parseKeyMaterial(fields []string) KeyMaterial {
	return KeyMaterial{
		KeyID:        field(fields, fieldKeyID),
		Validity:     field(fields, fieldValidity),
		Algo:         atoiOrZero(field(fields, fieldAlgo)),
		Length:       atoiOrZero(field(fields, fieldKeyLength)),
		Curve:        field(fields, fieldCurve),
		Created:      parseColonTime(field(fields, fieldCreated)),
		Expires:      parseColonTime(field(fields, fieldExpires)),
		Capabilities: field(fields, fieldCapabilities),
	}
}

func field(fields []string, index int) string {
	if index >= len(fields) {
		return ""
	}
	return fields[index]
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// parseColonTime accepts seconds since epoch or ISO 8601 basic format, per DETAILS.
func parseColonTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if seconds, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC()
	}
	if parsed, err := time.Parse("20060102T150405", s); err == nil {
		return parsed
	}
	return time.Time{}
}

// unescapeColonField decodes gpg's \xNN escapes (used for ':', '\' and control bytes).
func unescapeColonField(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		hasEscape := s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x'
		if hasEscape {
			if decoded, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(decoded))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// IsFingerprint reports whether s is a v4 (40 hex) or v5/v6 (64 hex) fingerprint
// in gpg's canonical upper-case form.
func IsFingerprint(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		isUpperHex := c >= '0' && c <= '9' || c >= 'A' && c <= 'F'
		if !isUpperHex {
			return false
		}
	}
	return true
}
