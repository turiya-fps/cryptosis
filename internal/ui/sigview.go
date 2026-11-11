package ui

import (
	"context"
	"fmt"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

// printSignatures reports every signature gpg verified for one operation.
// Signature data (user IDs especially) is untrusted and sanitized here.
func (a *App) printSignatures(statuses gpg.Statuses) []gpg.Signature {
	signatures := gpg.ParseSignatures(statuses)
	if len(signatures) == 0 {
		fmt.Fprintln(a.out, "Not signed.")
		return signatures
	}
	for _, sig := range signatures {
		a.printSignature(sig)
	}
	return signatures
}

// reportSignatures prints the signature report and, when a signer's key is
// missing, offers to fetch it from the keyserver.
func (a *App) reportSignatures(ctx context.Context, statuses gpg.Statuses) {
	signatures := a.printSignatures(statuses)
	for _, sig := range signatures {
		if !sig.ErrNoPubKey {
			continue
		}
		query := sig.KeyID
		if sig.Fingerprint != "" {
			query = sig.Fingerprint
		}
		fmt.Fprintln(a.out)
		fetch, err := a.askConfirm(fmt.Sprintf("Fetch key %s from %s?", sanitize.Line(groupFingerprint(query)), sanitize.Line(a.Config.Keyserver)), true)
		if err != nil || !fetch {
			return
		}
		if err := a.fetchKeyByFingerprint(ctx, query); err != nil {
			a.printError(err)
		}
		fmt.Fprintln(a.out, "Run the operation again to see the signature result.")
		return
	}
}

func (a *App) printSignature(sig gpg.Signature) {
	switch sig.Outcome {
	case gpg.SigGood:
		fmt.Fprintf(a.out, "Good signature by %s\n", sigIdentity(sig))
	case gpg.SigBad:
		fmt.Fprintf(a.out, "BAD signature claiming %s\n", sigIdentity(sig))
		fmt.Fprintln(a.out, "  The content was modified, or the key does not belong to this identity.")
	case gpg.SigError:
		if sig.ErrNoPubKey {
			fmt.Fprintf(a.out, "Signature NOT verified: key %s is not in your keyring\n", sanitize.Line(sig.KeyID))
			fmt.Fprintln(a.out, "  The signer's public key can be fetched below.")
		} else {
			fmt.Fprintf(a.out, "Signature NOT verified: gpg error %s for key %s\n", sanitize.Line(sig.ErrorCode), sanitize.Line(sig.KeyID))
		}
	case gpg.SigExpired:
		fmt.Fprintf(a.out, "Expired signature by %s\n", sigIdentity(sig))
	case gpg.SigExpiredKey:
		fmt.Fprintf(a.out, "Signature by %s made with an expired key\n", sigIdentity(sig))
	case gpg.SigRevokedKey:
		fmt.Fprintf(a.out, "Signature by %s made with a revoked key\n", sigIdentity(sig))
	default:
		fmt.Fprintf(a.out, "Signature outcome unknown (key %s)\n", sanitize.Line(sig.KeyID))
	}
	if sig.Outcome == gpg.SigGood {
		details := "trust: " + describeTrustKeyword(sig.TrustKeyword)
		if sig.Created != "" {
			details += ", made " + sanitize.Line(sig.Created)
		}
		fmt.Fprintf(a.out, "  %s\n", details)
	}
}

// sigIdentity describes who signed: full fingerprint when gpg reported it.
func sigIdentity(sig gpg.Signature) string {
	uid := truncateRunes(sanitize.Line(sig.UserID), pickerUserIDRunes)
	if uid == "" {
		uid = "(no user ID)"
	}
	if sig.Fingerprint != "" {
		return uid + " " + groupFingerprint(sig.Fingerprint)
	}
	return uid + " " + sanitize.Line(sig.KeyID)
}

func describeTrustKeyword(keyword string) string {
	switch keyword {
	case "TRUST_UNDEFINED", "TRUST_NEVER", "":
		return "untrusted"
	case "TRUST_MARGINAL":
		return "marginal"
	case "TRUST_FULLY":
		return "full"
	case "TRUST_ULTIMATE":
		return "ultimate"
	default:
		return sanitize.Line(keyword)
	}
}
