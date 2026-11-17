package gpg

import "testing"

// Status fixtures follow gpg 2.5.24 output (KEY_CONSIDERED etc. trimmed).
const (
	fixtureErrsigNoPubKey = "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 3CC0D7A6A6C4C352 22 10 00 1794909123 9 1514ED5CCE781269BF2732173CC0D7A6A6C4C352\n[GNUPG:] NO_PUBKEY 3CC0D7A6A6C4C352\n"
	fixtureDecryptOK      = "[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n[GNUPG:] END_DECRYPTION\n"
	fixtureGoodSig        = "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 438F68FF5D06DB72 Alice <alice@example.org>\n[GNUPG:] VALIDSIG BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72 2026-11-17 1794909123\n"
	fixtureBadSig         = "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 3CC0D7A6A6C4C352 Signer <s@example.org>\n"
	fixtureExitFailure    = "[GNUPG:] FAILURE gpg-exit 33554433\n"
	fixturePlaintext      = "[GNUPG:] PLAINTEXT 62 1794909123 \n"
)

func TestDecryptSucceeded(t *testing.T) {
	tests := []struct {
		name   string
		exit   int
		status string
		want   bool
	}{
		{"encrypted, exit 0", 0, fixturePlaintext + fixtureDecryptOK, true},
		{"encrypted and signed, exit 0", 0, fixturePlaintext + fixtureGoodSig + fixtureDecryptOK, true},
		{"inline-signed only, exit 0", 0, fixturePlaintext + fixtureGoodSig, true},
		{"no data, exit 0", 0, "[GNUPG:] NODATA 1\n", false},
		{"END_DECRYPTION alone, exit 0", 0, "[GNUPG:] END_DECRYPTION\n", false},
		{"encrypted, signer key missing", 2, fixturePlaintext + fixtureErrsigNoPubKey + fixtureDecryptOK + fixtureExitFailure, true},
		{"good and missing-key signatures", 2, fixturePlaintext + fixtureGoodSig + fixtureErrsigNoPubKey + fixtureDecryptOK + fixtureExitFailure, true},
		{"signed only, signer key missing", 2, fixturePlaintext + fixtureErrsigNoPubKey + fixtureExitFailure, false},
		{"bad signature", 1, fixturePlaintext + fixtureBadSig + fixtureExitFailure, false},
		{"missing key and bad signature", 2, fixturePlaintext + fixtureErrsigNoPubKey + fixtureBadSig + fixtureDecryptOK + fixtureExitFailure, false},
		{"ERRSIG other than missing key", 2, fixturePlaintext + "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 3CC0D7A6A6C4C352 99 10 00 1794909123 4\n" + fixtureDecryptOK + fixtureExitFailure, false},
		{"non-zero exit without signatures", 2, fixturePlaintext + fixtureDecryptOK + fixtureExitFailure, false},
		{"integrity failure still ends with END_DECRYPTION", 2, "[GNUPG:] BEGIN_DECRYPTION\n[GNUPG:] ERROR aead_checktag 16777226\n[GNUPG:] BADMDC\n[GNUPG:] DECRYPTION_FAILED\n[GNUPG:] END_DECRYPTION\n" + fixtureExitFailure, false},
		{"ERROR line next to missing key", 2, fixturePlaintext + fixtureErrsigNoPubKey + "[GNUPG:] ERROR proc_pkt.plaintext 89\n" + fixtureDecryptOK + fixtureExitFailure, false},
		{"FAILURE other than gpg-exit", 2, fixturePlaintext + fixtureErrsigNoPubKey + fixtureDecryptOK + "[GNUPG:] FAILURE decrypt 33587281\n" + fixtureExitFailure, false},
	}
	for _, tt := range tests {
		result := Result{ExitCode: tt.exit, Status: ParseStatus([]byte(tt.status))}
		if got := DecryptSucceeded(result); got != tt.want {
			t.Errorf("%s: DecryptSucceeded = %v, want %v", tt.name, got, tt.want)
		}
	}
}
