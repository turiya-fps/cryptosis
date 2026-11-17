package gpg

// DecryptSucceeded reports whether a --decrypt run produced output that may be
// delivered.
//
// With exit code 0 it requires DECRYPTION_OKAY, or PLAINTEXT for unencrypted
// inline-signed data. END_DECRYPTION is no success signal: gpg also emits it
// after DECRYPTION_FAILED.
//
// gpg also exits non-zero when decryption and its integrity check succeeded
// but a signer's key is missing (ERRSIG code 9 next to DECRYPTION_OKAY). That
// output is accepted; anything else with a non-zero exit is not: a bad,
// unknown or otherwise unverifiable signature, an ERROR line, or unencrypted
// signed data whose signature cannot be checked.
func DecryptSucceeded(r Result) bool {
	if r.Status.Has("DECRYPTION_FAILED") || r.Status.Has("BADMDC") || hasFailureOtherThanExit(r.Status) {
		return false
	}
	if r.ExitCode == 0 {
		return r.Status.Has("DECRYPTION_OKAY") || r.Status.Has("PLAINTEXT")
	}
	if !r.Status.Has("DECRYPTION_OKAY") || r.Status.Has("ERROR") {
		return false
	}
	missingKey := false
	for _, sig := range ParseSignatures(r.Status) {
		switch {
		case sig.Outcome == SigError && sig.ErrNoPubKey:
			missingKey = true
		case sig.Outcome == SigBad, sig.Outcome == SigUnknown, sig.Outcome == SigError:
			return false
		}
	}
	return missingKey
}

// hasFailureOtherThanExit reports a FAILURE line other than the
// "FAILURE gpg-exit <code>" that accompanies every non-zero exit.
func hasFailureOtherThanExit(statuses Statuses) bool {
	for _, line := range statuses {
		if line.Keyword == "FAILURE" && (len(line.Args) == 0 || line.Args[0] != "gpg-exit") {
			return true
		}
	}
	return false
}
