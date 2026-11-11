package gpg

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/gpgtest"
)

func TestEncryptCommandArgv(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	plain := runner.Argv(EncryptCommand([]string{strings.Repeat("A", 40)}, "", false, false))
	signed := runner.Argv(EncryptCommand(
		[]string{strings.Repeat("A", 40), strings.Repeat("B", 40)},
		strings.Repeat("C", 40), true, true))

	wantPlain := "/usr/bin/gpg --batch --status-fd 3 --encrypt --recipient " + strings.Repeat("A", 40) + " --no-armor"
	if got := strings.Join(plain, " "); got != wantPlain {
		t.Errorf("plain = %q, want %q", got, wantPlain)
	}
	wantSigned := "/usr/bin/gpg --batch --status-fd 3 --encrypt --recipient " + strings.Repeat("A", 40) +
		" --recipient " + strings.Repeat("B", 40) +
		" --sign --local-user " + strings.Repeat("C", 40) +
		" --trust-model always --armor"
	if got := strings.Join(signed, " "); got != wantSigned {
		t.Errorf("signed = %q, want %q", got, wantSigned)
	}
}

func TestSignAndVerifyCommandArgv(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	detached := runner.Argv(SignCommand(SignDetached, strings.Repeat("A", 40), false))
	clearsignedArgv := runner.Argv(SignCommand(SignClearsign, "", false))
	verify := runner.Argv(VerifyCommand("/tmp/doc.sig", "/tmp/doc"))

	if got := strings.Join(detached, " "); got != "/usr/bin/gpg --batch --status-fd 3 --detach-sign --local-user "+strings.Repeat("A", 40)+" --no-armor" {
		t.Errorf("detached = %q", got)
	}
	if got := strings.Join(clearsignedArgv, " "); got != "/usr/bin/gpg --batch --status-fd 3 --clearsign" {
		t.Errorf("clearsign = %q", got)
	}
	if got := strings.Join(verify, " "); !strings.HasSuffix(got, "--verify -- /tmp/doc.sig /tmp/doc") {
		t.Errorf("verify = %q", got)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Own <own@example.org>")
	plaintext := []byte("secret plans\nsecond line\n")
	ctx := context.Background()

	encrypted, err := runner.Run(ctx, EncryptCommand([]string{fpr}, "", false, false).WithStdin(bytes.NewReader(plaintext)))
	if err != nil || !encrypted.Succeeded("BEGIN_ENCRYPTION", "END_ENCRYPTION") {
		t.Fatalf("encrypt: err=%v exit=%d status=%+v stderr=%s", err, encrypted.ExitCode, encrypted.Status, encrypted.Stderr)
	}
	if bytes.Contains(encrypted.Stdout, plaintext) || len(encrypted.Stdout) == 0 {
		t.Errorf("ciphertext missing or contains plaintext: %q", encrypted.Stdout)
	}

	decrypted, err := runner.Run(ctx, DecryptCommand().WithStdin(bytes.NewReader(encrypted.Stdout)))
	if err != nil || !decrypted.Succeeded("BEGIN_DECRYPTION", "END_DECRYPTION") {
		t.Fatalf("decrypt: err=%v exit=%d status=%+v stderr=%s", err, decrypted.ExitCode, decrypted.Status, decrypted.Stderr)
	}
	if !bytes.Equal(decrypted.Stdout, plaintext) {
		t.Errorf("round trip = %q, want %q", decrypted.Stdout, plaintext)
	}
	if len(ParseSignatures(decrypted.Status)) != 0 {
		t.Errorf("unsigned message reported signatures: %+v", ParseSignatures(decrypted.Status))
	}
}

func TestEncryptSignDecryptReportsSignature(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Own <own@example.org>")
	ctx := context.Background()

	encrypted, err := runner.Run(ctx, EncryptCommand([]string{fpr}, fpr, false, true).WithStdin(strings.NewReader("hello")))
	if err != nil || !encrypted.Succeeded("END_ENCRYPTION") {
		t.Fatalf("encrypt+sign: err=%v exit=%d stderr=%s", err, encrypted.ExitCode, encrypted.Stderr)
	}
	decrypted, err := runner.Run(ctx, DecryptCommand().WithStdin(bytes.NewReader(encrypted.Stdout)))
	if err != nil || !decrypted.Succeeded("END_DECRYPTION") {
		t.Fatalf("decrypt: err=%v exit=%d stderr=%s", err, decrypted.ExitCode, decrypted.Stderr)
	}

	signatures := ParseSignatures(decrypted.Status)
	if len(signatures) != 1 || signatures[0].Outcome != SigGood || signatures[0].Fingerprint != fpr {
		t.Fatalf("signatures = %+v, want one good signature by %s", signatures, fpr)
	}
	if signatures[0].TrustKeyword != "TRUST_ULTIMATE" {
		t.Errorf("trust = %q, want TRUST_ULTIMATE for own key", signatures[0].TrustKeyword)
	}
	if !strings.Contains(signatures[0].UserID, "own@example.org") {
		t.Errorf("user id = %q", signatures[0].UserID)
	}
}

func TestEncryptToUntrustedKeyNeedsTrustModelAlways(t *testing.T) {
	peer, peerHome := newTestRunner(t)
	peerFpr := gpgtest.GenerateKey(t, peer.Bin(), peerHome, "Peer <peer@example.org>")
	peerKey := exportPublicKey(t, peer.Bin(), peerHome, peerFpr)
	runner, _ := newTestRunner(t)
	if _, err := runner.Run(context.Background(), ImportCommand().WithStdin(bytes.NewReader(peerKey))); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	refused, err := runner.Run(ctx, EncryptCommand([]string{peerFpr}, "", false, false).WithStdin(strings.NewReader("data")))
	if err != nil {
		t.Fatal(err)
	}
	if refused.Succeeded("END_ENCRYPTION") {
		t.Fatalf("encryption to unverified key unexpectedly worked: %+v", refused.Status)
	}

	allowed, err := runner.Run(ctx, EncryptCommand([]string{peerFpr}, "", true, false).WithStdin(strings.NewReader("data")))
	if err != nil || !allowed.Succeeded("END_ENCRYPTION") {
		t.Fatalf("encrypt with --trust-model always: err=%v exit=%d stderr=%s", err, allowed.ExitCode, allowed.Stderr)
	}
}

func TestDetachedSignAndVerify(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Signer <signer@example.org>")
	data := []byte("the document")
	ctx := context.Background()

	sign, err := runner.Run(ctx, SignCommand(SignDetached, fpr, false).WithStdin(bytes.NewReader(data)))
	if err != nil || !sign.Succeeded("SIG_CREATED") {
		t.Fatalf("sign: err=%v exit=%d stderr=%s", err, sign.ExitCode, sign.Stderr)
	}

	sigPath := testFile(t, "doc.sig", sign.Stdout)
	docPath := testFile(t, "doc", data)
	verified, err := runner.Run(ctx, VerifyCommand(sigPath, docPath))
	if err != nil || verified.ExitCode != 0 {
		t.Fatalf("verify: err=%v exit=%d stderr=%s", err, verified.ExitCode, verified.Stderr)
	}
	if sigs := ParseSignatures(verified.Status); len(sigs) != 1 || sigs[0].Fingerprint != fpr {
		t.Errorf("signatures = %+v", sigs)
	}

	corrupted := append([]byte(nil), sign.Stdout...)
	corrupted[len(corrupted)-10] ^= 0xff // corrupt inside the signature MPI, not the unhashed subpackets
	sigPath = testFile(t, "doc.sig", corrupted)
	tampered, err := runner.Run(ctx, VerifyCommand(sigPath, docPath))
	if err != nil {
		t.Fatal(err)
	}
	if tampered.ExitCode == 0 {
		t.Errorf("corrupted signature verified: exit=%d", tampered.ExitCode)
	}
	if sigs := ParseSignatures(tampered.Status); len(sigs) != 1 || sigs[0].Outcome != SigBad {
		t.Errorf("signatures = %+v, want one bad", sigs)
	}
}

func TestClearsignDecryptExtractsAndVerifies(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Signer <signer@example.org>")
	message := "line one\nline two\n"
	ctx := context.Background()

	signed, err := runner.Run(ctx, SignCommand(SignClearsign, fpr, false).WithStdin(strings.NewReader(message)))
	if err != nil || !signed.Succeeded("SIG_CREATED") {
		t.Fatalf("clearsign: err=%v exit=%d stderr=%s", err, signed.ExitCode, signed.Stderr)
	}
	if kind := DetectArmor(signed.Stdout); kind != ArmorSignedMessage {
		t.Fatalf("clearsign output classified %v", kind)
	}

	verified, err := runner.Run(ctx, DecryptCommand().WithStdin(bytes.NewReader(signed.Stdout)))
	if err != nil || verified.ExitCode != 0 {
		t.Fatalf("verify clearsign: err=%v exit=%d stderr=%s", err, verified.ExitCode, verified.Stderr)
	}
	if !strings.Contains(string(verified.Stdout), message) {
		t.Errorf("extracted text %q lacks original", verified.Stdout)
	}
	if sigs := ParseSignatures(verified.Status); len(sigs) != 1 || sigs[0].Outcome != SigGood {
		t.Errorf("signatures = %+v, want one good", sigs)
	}

	tampered := bytes.Replace(signed.Stdout, []byte("line one"), []byte("line 0ne"), 1)
	bad, err := runner.Run(ctx, DecryptCommand().WithStdin(bytes.NewReader(tampered)))
	if err != nil {
		t.Fatal(err)
	}
	if bad.ExitCode == 0 {
		t.Errorf("tampered clearsign verified: exit=%d", bad.ExitCode)
	}
	if sigs := ParseSignatures(bad.Status); len(sigs) != 1 || sigs[0].Outcome != SigBad {
		t.Errorf("signatures = %+v, want one bad", sigs)
	}
	// gpg still emits the message text when the signature fails; the UI can
	// offer to keep it with a warning.
	if !strings.Contains(string(bad.Stdout), "line 0ne") {
		t.Errorf("text of tampered message not extracted: %q", bad.Stdout)
	}
}

func TestVerifyUnknownKeyReportsERRSIG(t *testing.T) {
	peer, peerHome := newTestRunner(t)
	peerFpr := gpgtest.GenerateKey(t, peer.Bin(), peerHome, "Stranger <stranger@example.org>")
	signature := signDetachedExternally(t, peer.Bin(), peerHome, peerFpr, []byte("doc"))
	runner, _ := newTestRunner(t) // does not know the peer's key
	docPath := testFile(t, "doc", []byte("doc"))
	sigPath := testFile(t, "doc.sig", signature)

	result, err := runner.Run(context.Background(), VerifyCommand(sigPath, docPath))
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("verification without the key succeeded: exit=%d", result.ExitCode)
	}
	signatures := ParseSignatures(result.Status)
	if len(signatures) != 1 || signatures[0].Outcome != SigError || !signatures[0].ErrNoPubKey {
		t.Fatalf("signatures = %+v, want one ERRSIG no-public-key", signatures)
	}
	if want := peerFpr[len(peerFpr)-16:]; signatures[0].KeyID != want {
		t.Errorf("key id = %q, want %q", signatures[0].KeyID, want)
	}
}

func TestParseSignaturesGroupsLines(t *testing.T) {
	statuses := ParseStatus([]byte(
		"[GNUPG:] NEWSIG\n" +
			"[GNUPG:] GOODSIG ABCDEF0123456789 Alice <alice@example.org>\n" +
			"[GNUPG:] VALIDSIG " + strings.Repeat("A", 40) + " 2026-11-10 1778714400\n" +
			"[GNUPG:] TRUST_FULLY\n" +
			"[GNUPG:] NEWSIG " + strings.Repeat("C", 16) + "\n" +
			"[GNUPG:] ERRSIG " + strings.Repeat("C", 16) + " 22 18 1 1778714400 9 " + strings.Repeat("C", 40) + "\n" +
			"[GNUPG:] NEWSIG\n" +
			"[GNUPG:] BADSIG DEADBEEFDEADBEEF Mallory \x1b[31minjected\x1b[0m\n"))

	signatures := ParseSignatures(statuses)

	if len(signatures) != 3 {
		t.Fatalf("got %d signatures, want 3: %+v", len(signatures), signatures)
	}
	first := signatures[0]
	if first.KeyID != "ABCDEF0123456789" || first.UserID != "Alice <alice@example.org>" || first.Outcome != SigGood {
		t.Errorf("first = %+v", first)
	}
	if first.Fingerprint != strings.Repeat("A", 40) || first.Created != "2026-11-10" || first.TrustKeyword != "TRUST_FULLY" {
		t.Errorf("first validsig fields = %+v", first)
	}
	second := signatures[1]
	if second.Outcome != SigError || !second.ErrNoPubKey || second.KeyID != strings.Repeat("C", 16) {
		t.Errorf("second = %+v", second)
	}
	if second.Fingerprint != strings.Repeat("C", 40) {
		t.Errorf("second fingerprint = %q, want the ERRSIG argument", second.Fingerprint)
	}
	third := signatures[2]
	if third.Outcome != SigBad || !strings.Contains(third.UserID, "Mallory") {
		t.Errorf("third = %+v", third)
	}
}

func TestParseSignaturesWithoutNEWSIG(t *testing.T) {
	statuses := ParseStatus([]byte(
		"[GNUPG:] GOODSIG AAAABBBBCCCCDDDD Bob <bob@example.org>\n" +
			"[GNUPG:] TRUST_MARGINAL\n"))

	signatures := ParseSignatures(statuses)

	if len(signatures) != 1 || signatures[0].KeyID != "AAAABBBBCCCCDDDD" || signatures[0].TrustKeyword != "TRUST_MARGINAL" {
		t.Errorf("signatures = %+v", signatures)
	}
}

func TestDetectArmor(t *testing.T) {
	cases := map[string]ArmorKind{
		"-----BEGIN PGP MESSAGE-----\n\nabc\n":                 ArmorMessage,
		"leading note\n-----BEGIN PGP SIGNATURE-----\n\nabc\n": ArmorSignature,
		"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n":   ArmorSignedMessage,
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n":               ArmorPublicKey,
		"-----BEGIN PGP PRIVATE KEY BLOCK-----\n":              ArmorPrivateKey,
		"not armor at all":                  ArmorNone,
		"\x85\x02\x0c\x03\x9f\x08binary":    ArmorNone,
		"-----BEGIN PGP WEIRD THING-----\n": ArmorNone,
	}
	for data, want := range cases {
		if got := DetectArmor([]byte(data)); got != want {
			t.Errorf("DetectArmor(%q) = %v, want %v", data, got, want)
		}
	}
}

func testFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signDetachedExternally(t *testing.T, bin, home, fpr string, data []byte) []byte {
	t.Helper()
	sign := exec.Command(bin, "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--status-fd", "2", "--local-user", fpr, "--detach-sign")
	sign.Stdin = bytes.NewReader(data)
	var status bytes.Buffer
	sign.Stderr = &status
	signature, err := sign.Output()
	if err != nil {
		t.Fatalf("external detached sign: %v", err)
	}
	if !bytes.Contains(status.Bytes(), []byte("SIG_CREATED")) {
		t.Fatalf("no SIG_CREATED in %q", status.String())
	}
	return signature
}
