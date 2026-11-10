package gpg

import (
	"strconv"
	"strings"
)

// Ownertrust is an owner-trust level on gpg's internal 2-6 scale (trustdb.h:
// TRUST_UNDEFINED..TRUST_ULTIMATE), the same numeric scale used by
// --import-ownertrust and --export-ownertrust files. gpg 2.4+ also accepts
// these as words to --quick-set-ownertrust.
type Ownertrust int

// Settable ownertrust levels, lowest to highest.
const (
	OwnertrustUndefined Ownertrust = 2
	OwnertrustNever     Ownertrust = 3
	OwnertrustMarginal  Ownertrust = 4
	OwnertrustFull      Ownertrust = 5
	OwnertrustUltimate  Ownertrust = 6
)

// Valid reports whether t is one of the settable levels.
func (t Ownertrust) Valid() bool {
	return t >= OwnertrustUndefined && t <= OwnertrustUltimate
}

// Word returns the --quick-set-ownertrust word for t.
func (t Ownertrust) Word() string {
	switch t {
	case OwnertrustUndefined:
		return "undefined"
	case OwnertrustNever:
		return "never"
	case OwnertrustMarginal:
		return "marginal"
	case OwnertrustFull:
		return "full"
	case OwnertrustUltimate:
		return "ultimate"
	default:
		return ""
	}
}

// String returns the level's display name.
func (t Ownertrust) String() string {
	switch t {
	case OwnertrustUndefined:
		return "Undefined"
	case OwnertrustNever:
		return "Never"
	case OwnertrustMarginal:
		return "Marginal"
	case OwnertrustFull:
		return "Full"
	case OwnertrustUltimate:
		return "Ultimate"
	default:
		return "Unknown"
	}
}

// ParseOwnertrustExport maps fingerprints to ownertrust from
// --export-ownertrust output. Comments, malformed lines and values outside the
// settable range (e.g. legacy 1) are skipped.
func ParseOwnertrustExport(data []byte) map[string]Ownertrust {
	trust := make(map[string]Ownertrust)
	for _, line := range strings.Split(string(data), "\n") {
		fpr, rest, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || !IsFingerprint(fpr) {
			continue
		}
		value, _, _ := strings.Cut(rest, ":")
		level, err := strconv.Atoi(value)
		if err != nil || !Ownertrust(level).Valid() {
			continue
		}
		trust[fpr] = Ownertrust(level)
	}
	return trust
}
