package gpg

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turiya-fps/cryptosis/internal/fsout"
	"github.com/turiya-fps/cryptosis/internal/gpgtest"
)

// exportOwnertrustValue reads the ownertrust of fpr from gpg's export format
// ("FPR:N:"), the same scale on every supported gpg version.
func exportOwnertrustValue(t *testing.T, bin, home, fpr string) string {
	t.Helper()
	out, err := exec.Command(bin, "--homedir", home, "--batch", "--export-ownertrust").Output()
	if err != nil {
		t.Fatalf("export-ownertrust: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, fpr+":") {
			return strings.Split(line, ":")[1]
		}
	}
	return ""
}

func listOneKey(t *testing.T, runner *Runner, fpr string, secret bool) Key {
	t.Helper()
	listing, err := runner.Run(context.Background(), ListKeysCommand(secret))
	if err != nil || !listing.Succeeded() {
		t.Fatalf("list: err=%v exit=%d stderr=%s", err, listing.ExitCode, listing.Stderr)
	}
	keys, err := ParseKeys(listing.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key.Fingerprint == fpr {
			return key
		}
	}
	t.Fatalf("key %s not found in listing of %d keys", fpr, len(keys))
	return Key{}
}

func TestQuickGenerateKeyCreatesModernKeyWithSubkey(t *testing.T) {
	runner, home := newTestRunner(t)
	command := QuickGenerateKeyCommand("Gen <gen@example.org>", "future-default", "2y")

	result, err := runner.Run(context.Background(), command)

	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !result.Succeeded("KEY_CREATED") {
		t.Fatalf("generate: exit=%d status keywords=%v stderr=%s", result.ExitCode, result.Status, result.Stderr)
	}
	fpr, ok := PrimaryFingerprint(result.Status)
	if !ok || !IsFingerprint(fpr) {
		t.Fatalf("PrimaryFingerprint(%v) = %q", result.Status, fpr)
	}
	key := listOneKey(t, runner, fpr, false)
	// Lowercase = primary's own usage, uppercase = usable caps of the whole key.
	if key.Curve != "ed25519" || key.Algo != 22 || key.Capabilities != "scESC" {
		t.Errorf("primary = %s algo %d caps %q, want ed25519 algo 22 caps scESC", key.Curve, key.Algo, key.Capabilities)
	}
	if len(key.Subkeys) != 1 || key.Subkeys[0].Curve != "cv25519" || key.Subkeys[0].Algo != 18 {
		t.Errorf("subkeys = %+v, want one cv25519 ECDH subkey", key.Subkeys)
	}
	if key.Expires.IsZero() {
		t.Error("primary key has no expiry despite 2y requested")
	}
	// gpg writes a revocation certificate next to the keyring.
	revocs := filepath.Join(home, "openpgp-revocs.d", fpr+".rev")
	if _, err := os.Stat(revocs); err != nil {
		t.Errorf("revocation certificate: %v", err)
	}
}

func TestQuickGenerateKeyPlacesUserIDAfterDoubleDash(t *testing.T) {
	runner := &Runner{bin: "/usr/bin/gpg"}

	argv := strings.Join(runner.Argv(QuickGenerateKeyCommand("--yes <a@example.org>", "future-default", "2y")), " ")

	want := "/usr/bin/gpg --batch --status-fd 3 --quick-generate-key -- --yes <a@example.org> future-default default 2y"
	if argv != want {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestImportPreviewThenImportSameBytes(t *testing.T) {
	source, sourceHome := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, source.Bin(), sourceHome, "Source <src@example.org>")
	exported, err := exec.Command(source.Bin(), "--homedir", sourceHome, "--batch", "--export", "--", fpr).Output()
	if err != nil {
		t.Fatal(err)
	}
	target, _ := newTestRunner(t)

	preview, err := target.Run(context.Background(), ImportPreviewCommand().WithStdin(bytes.NewReader(exported)))
	if err != nil || !preview.Succeeded() {
		t.Fatalf("show-only: err=%v exit=%d stderr=%s", err, preview.ExitCode, preview.Stderr)
	}
	keys, err := ParseKeys(preview.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != fpr {
		t.Fatalf("preview keys = %+v, want %s", keys, fpr)
	}
	// show-only must not touch the keyring.
	if stillEmpty, _ := target.Run(context.Background(), ListKeysCommand(false)); bytes.Contains(stillEmpty.Stdout, []byte(fpr)) {
		t.Fatal("show-only imported the key")
	}

	imported, err := target.Run(context.Background(), ImportCommand().WithStdin(bytes.NewReader(exported)))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !imported.Succeeded("IMPORT_OK", "IMPORT_RES") {
		t.Fatalf("import: exit=%d status=%v stderr=%s", imported.ExitCode, imported.Status, imported.Stderr)
	}
	summary, ok := ParseImportSummary(imported.Status)
	if !ok || summary.Imported != 1 || summary.Count != 1 {
		t.Errorf("summary = %+v ok=%v, want 1 new key of 1 read", summary, ok)
	}
	listOneKey(t, target, fpr, false)
}

func TestImportSummaryParsesIMPORTRESFields(t *testing.T) {
	statuses := ParseStatus([]byte("[GNUPG:] IMPORT_RES 3 0 2 0 1 1 2 4 0 1 1 0 0 0 0\n"))

	summary, ok := ParseImportSummary(statuses)

	if !ok {
		t.Fatal("no IMPORT_RES")
	}
	want := ImportSummary{Count: 3, Imported: 2, Unchanged: 1, NewUIDs: 1, NewSubkeys: 2, NewSignatures: 4, SecretRead: 1, SecretImported: 1}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
}

func TestImportOKReasonNamesFlags(t *testing.T) {
	cases := map[int]string{
		0:  "already present",
		1:  "new key",
		3:  "new key, new user ID",
		4:  "new signatures",
		9:  "new key, new subkey",
		16: "contains a secret key",
	}
	for flags, want := range cases {
		if got := ImportOKReason(flags); got != want {
			t.Errorf("ImportOKReason(%d) = %q, want %q", flags, got, want)
		}
	}
}

func TestExportPublicAndSecretKeys(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Exported <exp@example.org>")

	public, err := runner.Run(context.Background(), ExportCommand([]string{fpr}, false, true))
	if err != nil || !public.Succeeded("EXPORTED") {
		t.Fatalf("export public: err=%v exit=%d stderr=%s", err, public.ExitCode, public.Stderr)
	}
	if !bytes.Contains(public.Stdout, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		t.Error("public export is not armored")
	}

	secret, err := runner.Run(context.Background(), ExportCommand([]string{fpr}, true, false))
	if err != nil || !secret.Succeeded("EXPORTED") {
		t.Fatalf("export secret: err=%v exit=%d stderr=%s", err, secret.ExitCode, secret.Stderr)
	}
	if tag := firstPacketTag(secret.Stdout); tag != secretKeyPacketTag {
		t.Errorf("binary secret export starts with packet tag %d, want %d (secret key)", tag, secretKeyPacketTag)
	}
}

const secretKeyPacketTag = 5

// firstPacketTag decodes the OpenPGP packet tag from the first CTB (RFC 9580
// 4.2): new format keeps it in bits 0-5, legacy format in bits 2-5.
func firstPacketTag(packets []byte) int {
	if len(packets) == 0 || packets[0]&0x80 == 0 {
		return -1
	}
	ctb := packets[0]
	if ctb&0x40 != 0 {
		return int(ctb & 0x3f)
	}
	return int(ctb>>2) & 0x0f
}

func TestDeleteKeys(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Doomed <gone@example.org>")

	// gpg refuses to delete the public part while the secret key exists.
	refused, err := runner.Run(context.Background(), DeleteCommand(fpr, false))
	if err != nil {
		t.Fatal(err)
	}
	if refused.ExitCode == 0 {
		t.Fatal("public-only delete of a key with secret succeeded")
	}

	deleted, err := runner.Run(context.Background(), DeleteCommand(fpr, true))
	if err != nil || !deleted.Succeeded() {
		t.Fatalf("delete secret+public: err=%v exit=%d stderr=%s", err, deleted.ExitCode, deleted.Stderr)
	}
	listing, _ := runner.Run(context.Background(), ListKeysCommand(true))
	if bytes.Contains(listing.Stdout, []byte(fpr)) {
		t.Error("key still listed after delete")
	}
}

func TestDeletePublicKeyWithoutSecret(t *testing.T) {
	runner, _ := newTestRunner(t)
	fpr := importOneForeignKey(t, runner)

	deleted, err := runner.Run(context.Background(), DeleteCommand(fpr, false))
	if err != nil || !deleted.Succeeded() {
		t.Fatalf("delete public: err=%v exit=%d stderr=%s", err, deleted.ExitCode, deleted.Stderr)
	}
	listing, _ := runner.Run(context.Background(), ListKeysCommand(false))
	if bytes.Contains(listing.Stdout, []byte(fpr)) {
		t.Error("public key still listed after delete")
	}
}

func importOneForeignKey(t *testing.T, runner *Runner) string {
	t.Helper()
	source, sourceHome := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, source.Bin(), sourceHome, "Foreign <foreign@example.org>")
	exported, err := exec.Command(source.Bin(), "--homedir", sourceHome, "--batch", "--export", "--", fpr).Output()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := runner.Run(context.Background(), ImportCommand().WithStdin(bytes.NewReader(exported)))
	if err != nil || !imported.Succeeded("IMPORT_OK") {
		t.Fatalf("import: err=%v exit=%d stderr=%s", err, imported.ExitCode, imported.Stderr)
	}
	return fpr
}

func TestQuickSetExpireOnPrimaryKeyAndSubkey(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Expiring <exp2@example.org>")
	key := listOneKey(t, runner, fpr, false)
	subkeyFpr := key.Subkeys[0].Fingerprint

	primary, err := runner.Run(context.Background(), QuickSetExpireCommand(fpr, "18m", ""))
	if err != nil || !primary.Succeeded() {
		t.Fatalf("set expire: err=%v exit=%d stderr=%s", err, primary.ExitCode, primary.Stderr)
	}
	key = listOneKey(t, runner, fpr, false)
	want := key.Created.Add(18 * 30 * 24 * time.Hour).Unix()
	if diff := key.Expires.Unix() - want; diff < 0 || diff > 31*24*3600 {
		t.Errorf("primary expires %v, want ~18 months after creation", key.Expires)
	}

	// gpg 2.5 creates the future-default subkey without expiry, so set a finite one.
	subkey, err := runner.Run(context.Background(), QuickSetExpireCommand(fpr, "1y", subkeyFpr))
	if err != nil || !subkey.Succeeded() {
		t.Fatalf("set subkey expire: err=%v exit=%d stderr=%s", err, subkey.ExitCode, subkey.Stderr)
	}
	key = listOneKey(t, runner, fpr, false)
	untilSubkeyExpiry := time.Until(key.Subkeys[0].Expires)
	if untilSubkeyExpiry < 360*24*time.Hour || untilSubkeyExpiry > 367*24*time.Hour {
		t.Errorf("subkey expires %v, want ~1 year from now", key.Subkeys[0].Expires)
	}
}

func TestSetOwnertrustQuickAndFallback(t *testing.T) {
	runner, _ := newTestRunner(t)
	fpr := importOneForeignKey(t, runner)
	ctx := context.Background()

	info, err := runner.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var result Result
	if info.Capabilities.QuickSetOwnertrust {
		result, err = runner.Run(ctx, QuickSetOwnertrustCommand(fpr, OwnertrustMarginal))
	} else {
		result, err = runner.Run(ctx, ImportOwnertrustCommand(fpr, OwnertrustMarginal))
	}
	if err != nil || !result.Succeeded() {
		t.Fatalf("set ownertrust: err=%v exit=%d stderr=%s", err, result.ExitCode, result.Stderr)
	}
	if got := exportOwnertrustValue(t, runner.Bin(), runnerHome(t, runner), fpr); got != "4" {
		t.Errorf("ownertrust = %q, want 4 (marginal)", got)
	}

	// The fallback path must reach the same state on new gpgs, too.
	fallback, err := runner.Run(ctx, ImportOwnertrustCommand(fpr, OwnertrustFull))
	if err != nil || !fallback.Succeeded() {
		t.Fatalf("import-ownertrust: err=%v exit=%d stderr=%s", err, fallback.ExitCode, fallback.Stderr)
	}
	if got := exportOwnertrustValue(t, runner.Bin(), runnerHome(t, runner), fpr); got != "5" {
		t.Errorf("ownertrust = %q, want 5 (full)", got)
	}
}

func runnerHome(t *testing.T, runner *Runner) string {
	t.Helper()
	home, err := runner.HomeDir(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func TestParseOwnertrustExportSkipsCommentsAndLegacyValues(t *testing.T) {
	marginal := strings.Repeat("A", 40)
	legacy := strings.Repeat("B", 40)
	export := "# List of assigned trustvalues\n" + marginal + ":4:\n" + legacy + ":1:\nnot-a-fpr:5:\n"

	trust := ParseOwnertrustExport([]byte(export))

	if len(trust) != 1 || trust[marginal] != OwnertrustMarginal {
		t.Errorf("trust = %v, want only %s marginal", trust, marginal)
	}
}

func TestExportOwnertrustReflectsSetTrust(t *testing.T) {
	runner, _ := newTestRunner(t)
	fpr := importOneForeignKey(t, runner)
	ctx := context.Background()
	if set, err := runner.Run(ctx, ImportOwnertrustCommand(fpr, OwnertrustNever)); err != nil || !set.Succeeded() {
		t.Fatalf("import-ownertrust: err=%v exit=%d", err, set.ExitCode)
	}

	exported, err := runner.Run(ctx, ExportOwnertrustCommand())

	if err != nil || !exported.Succeeded() {
		t.Fatalf("export-ownertrust: err=%v exit=%d", err, exported.ExitCode)
	}
	if got := ParseOwnertrustExport(exported.Stdout)[fpr]; got != OwnertrustNever {
		t.Errorf("ownertrust = %v, want Never", got)
	}
}

func TestHasErrorCodeMatchesLastArgOfErrorLines(t *testing.T) {
	statuses := ParseStatus([]byte("[GNUPG:] ERROR keygen.passphrase 83886383\n[GNUPG:] FAILURE gpg-exit 33554433\n"))

	if !Statuses(statuses).HasErrorCode(ErrMissingEnvvar) {
		t.Error("missing-envvar ERROR line not detected")
	}
	if Statuses(statuses).HasErrorCode("83886179") {
		t.Error("absent code reported")
	}
}

func TestOwnertrustWordsAndNumbers(t *testing.T) {
	words := map[Ownertrust]string{
		OwnertrustUndefined: "undefined",
		OwnertrustNever:     "never",
		OwnertrustMarginal:  "marginal",
		OwnertrustFull:      "full",
		OwnertrustUltimate:  "ultimate",
	}
	for trust, word := range words {
		if !trust.Valid() || trust.Word() != word {
			t.Errorf("trust %d: Valid=%v Word=%q want %q", trust, trust.Valid(), trust.Word(), word)
		}
	}
	if (Ownertrust(1)).Valid() || (Ownertrust(7)).Valid() {
		t.Error("trust values outside 2-6 accepted")
	}
}

func TestGenRevokeWritesArmoredCertificate(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Revoker <rev@example.org>")
	dest := filepath.Join(t.TempDir(), "revoke.asc")
	out, err := fsout.Create(dest)
	if err != nil {
		t.Fatal(err)
	}
	command, err := GenRevokeCommand(fpr, RevokeCompromised, "laptop stolen")
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), command.WithStdout(out.Writer()))
	if err != nil {
		_ = out.Abort()
		t.Fatalf("run: %v stderr=%s", err, result.Stderr)
	}
	if !result.Succeeded() || !result.Status.Has("GOT_IT") {
		_ = out.Abort()
		t.Fatalf("gen-revoke: exit=%d status=%v stderr=%s", result.ExitCode, result.Status, result.Stderr)
	}
	if err := out.Commit(true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		t.Errorf("certificate = %q status=%v stderr=%s", data[:min(60, len(data))], result.Status, result.Stderr)
	}
}

func TestGenRevokeDeclineLeavesNoCertificate(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Keeper <keep@example.org>")
	answers, _ := GenRevokeAnswers(RevokeNoReason, "")
	answers[0].Answer = "n" // decline at "Create a revocation certificate for this key?"
	command := Command{
		label:   "Create revocation certificate",
		options: []string{"--gen-revoke", fpr},
		answers: answers,
	}

	result, err := runner.Run(context.Background(), command)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, result.Stderr)
	}
	if result.ExitCode != 0 {
		t.Fatalf("declined gen-revoke exit=%d stderr=%s", result.ExitCode, result.Stderr)
	}
	if len(result.Stdout) != 0 {
		t.Errorf("declined gen-revoke wrote %d bytes", len(result.Stdout))
	}
}

func TestGenRevokeUnexpectedPromptAborts(t *testing.T) {
	runner, home := newTestRunner(t)
	fpr := gpgtest.GenerateKey(t, runner.Bin(), home, "Queasy <q@example.org>")
	// Missing gen_revoke.okay answer: gpg's first prompt is unexpected.
	command := Command{
		label:   "Create revocation certificate",
		options: []string{"--gen-revoke", fpr},
		answers: []PromptAnswer{{Keyword: "ask_revocation_reason.code", Answer: "0"}},
	}

	result, err := runner.Run(context.Background(), command)

	if err == nil || !strings.Contains(err.Error(), "unexpected prompt") {
		t.Fatalf("err = %v, want unexpected-prompt error (exit=%d)", err, result.ExitCode)
	}
	if len(result.Stdout) != 0 {
		t.Errorf("aborted gen-revoke wrote %d bytes", len(result.Stdout))
	}
}
