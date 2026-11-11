package gpg

import "strconv"

// ImportSummary is the tail of an --import run, from the IMPORT_RES status
// line (gnupg doc/DETAILS, "Import/Export").
type ImportSummary struct {
	Count          int // keys read
	NoUserID       int // keys skipped for lacking a user ID
	Imported       int // entirely new keys
	Unchanged      int // keys already present without changes
	NewUIDs        int
	NewSubkeys     int
	NewSignatures  int
	NewRevocations int
	SecretRead     int
	SecretImported int
	NotImported    int
}

// ParseImportSummary reads the IMPORT_RES line of a finished import.
func ParseImportSummary(statuses Statuses) (ImportSummary, bool) {
	line, found := statuses.First("IMPORT_RES")
	if !found {
		return ImportSummary{}, false
	}
	field := func(i int) int {
		if i >= len(line.Args) {
			return 0
		}
		n, err := strconv.Atoi(line.Args[i])
		if err != nil {
			return 0
		}
		return n
	}
	return ImportSummary{
		Count:          field(0),
		NoUserID:       field(1),
		Imported:       field(2),
		Unchanged:      field(4),
		NewUIDs:        field(5),
		NewSubkeys:     field(6),
		NewSignatures:  field(7),
		NewRevocations: field(8),
		SecretRead:     field(9),
		SecretImported: field(10),
		NotImported:    field(13),
	}, true
}

// ImportOKReason names the IMPORT_OK flag bits for a friendly per-key report.
func ImportOKReason(flags int) string {
	switch {
	case flags == 0:
		return "already present"
	case flags&16 != 0:
		return "contains a secret key"
	default:
		var parts []string
		if flags&1 != 0 {
			parts = append(parts, "new key")
		}
		if flags&2 != 0 {
			parts = append(parts, "new user ID")
		}
		if flags&8 != 0 {
			parts = append(parts, "new subkey")
		}
		if flags&4 != 0 {
			parts = append(parts, "new signatures")
		}
		if len(parts) == 0 {
			return "updated"
		}
		return joinComma(parts)
	}
}

func joinComma(parts []string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += ", "
		}
		result += part
	}
	return result
}
