package gpg

import "strings"

// SigOutcome classifies the result of verifying one signature.
type SigOutcome int

const (
	// SigUnknown is the zero value: gpg reported no outcome line yet.
	SigUnknown SigOutcome = iota
	// SigGood means the signature verified.
	SigGood
	// SigBad means verification failed: content or identity is wrong.
	SigBad
	// SigError means gpg could not verify (e.g. missing key).
	SigError
	// SigExpired is an otherwise good signature past its expiry.
	SigExpired
	// SigExpiredKey was made by a key that has since expired.
	SigExpiredKey
	// SigRevokedKey was made by a key that has since been revoked.
	SigRevokedKey
)

// String returns a short human-readable outcome, used in summaries.
func (o SigOutcome) String() string {
	switch o {
	case SigGood:
		return "good signature"
	case SigBad:
		return "BAD signature"
	case SigError:
		return "not verified"
	case SigExpired:
		return "expired signature"
	case SigExpiredKey:
		return "signed with an expired key"
	case SigRevokedKey:
		return "signed with a revoked key"
	default:
		return "unknown"
	}
}

// Signature is the verification result for one signature of a message.
// UserID is untrusted: sanitize before display.
type Signature struct {
	KeyID        string // long key ID from the NEWSIG/GOODSIG-family line
	Fingerprint  string // full fingerprint from VALIDSIG, when present
	UserID       string
	Outcome      SigOutcome
	ErrorCode    string // ERRSIG's gpg error code argument
	ErrNoPubKey  bool   // ERRSIG because the signing key is not in the keyring
	Created      string // VALIDSIG's signature creation date
	Timestamp    string // VALIDSIG's signature timestamp
	TrustKeyword string // TRUST_* keyword, "" when gpg reported none
}

// ErrCodeNoPubKey is gpg's GPG_ERR_NO_PUBKEY, the ERRSIG code for a missing
// signing key.
const ErrCodeNoPubKey = "9"

// ParseSignatures groups the per-signature status lines (NEWSIG followed by
// GOODSIG/BADSIG/ERRSIG/..., VALIDSIG, TRUST_*) into one Signature each, in
// the order gpg reported them.
func ParseSignatures(statuses Statuses) []Signature {
	var signatures []Signature
	current := -1
	start := func() {
		signatures = append(signatures, Signature{})
		current = len(signatures) - 1
	}
	for _, line := range statuses {
		switch line.Keyword {
		case "NEWSIG":
			start()
			if len(line.Args) > 0 {
				signatures[current].KeyID = line.Args[0]
			}
			if len(line.Args) > 1 {
				signatures[current].UserID = strings.Join(line.Args[1:], " ")
			}
		case "GOODSIG", "BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "ERRSIG":
			// One outcome line per signature; start a new one when the current
			// signature already has its outcome (or the stream lacks NEWSIG).
			if current < 0 || signatures[current].Outcome != SigUnknown {
				start()
			}
			sig := &signatures[current]
			if len(line.Args) > 0 {
				sig.KeyID = line.Args[0]
			}
			if len(line.Args) > 1 {
				sig.UserID = strings.Join(line.Args[1:], " ")
			}
			switch line.Keyword {
			case "GOODSIG":
				sig.Outcome = SigGood
			case "BADSIG":
				sig.Outcome = SigBad
			case "EXPSIG":
				sig.Outcome = SigExpired
			case "EXPKEYSIG":
				sig.Outcome = SigExpiredKey
			case "REVKEYSIG":
				sig.Outcome = SigRevokedKey
			case "ERRSIG":
				sig.Outcome = SigError
				// ERRSIG <keyid> <pubkey algo> <hash algo> <sig class> <timestamp> <errcode> [<fpr>]
				if len(line.Args) > 5 {
					sig.ErrorCode = line.Args[5]
					sig.ErrNoPubKey = line.Args[5] == ErrCodeNoPubKey
				}
				if len(line.Args) > 6 && IsFingerprint(line.Args[6]) && sig.Fingerprint == "" {
					sig.Fingerprint = line.Args[6]
				}
			}
		case "VALIDSIG":
			if current < 0 || signatures[current].Fingerprint != "" {
				continue
			}
			signatures[current].Fingerprint = field(line.Args, 0)
			signatures[current].Created = field(line.Args, 1)
			signatures[current].Timestamp = field(line.Args, 2)
		case "TRUST_UNDEFINED", "TRUST_NEVER", "TRUST_MARGINAL", "TRUST_FULLY", "TRUST_ULTIMATE":
			if current >= 0 && signatures[current].TrustKeyword == "" {
				signatures[current].TrustKeyword = line.Keyword
			}
		}
	}
	return signatures
}
