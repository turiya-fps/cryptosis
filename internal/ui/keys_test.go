package ui

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turiya-fps/cryptosis/internal/config"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/gpgtest"
)

func newTestApp(t *testing.T) (*App, *bytes.Buffer, string) {
	t.Helper()
	bin := gpgtest.Binary(t)
	home := gpgtest.NewHome(t, bin)
	runner, err := gpg.NewRunner(bin, home)
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	app := New(Startup{Runner: runner, Config: config.Default()}, out)
	return app, out, home
}

func TestRenderKeyTableSanitizesAndTruncatesUserIDs(t *testing.T) {
	hostileUID := "Mallory \x1b[31mRED\x1b[0m " + strings.Repeat("x", 60)
	key := gpg.Key{
		KeyMaterial: gpg.KeyMaterial{Fingerprint: strings.Repeat("A", 40), KeyID: "AAAAAAAAAAAAAAAA", Validity: "f", Algo: 22, Curve: "ed25519", Capabilities: "scESC"},
		UIDs:        []gpg.UID{{UserID: hostileUID}},
	}
	ring := &keyring{keys: []gpg.Key{key}, hasSecret: map[string]bool{key.Fingerprint: true}}
	var out bytes.Buffer

	renderKeyTable(&out, ring, time.Now())

	rendered := out.String()
	if strings.ContainsRune(rendered, '\x1b') {
		t.Errorf("escape sequence reached the table: %q", rendered)
	}
	for _, want := range []string{"sec", "full", "never", "sign, encrypt, certify", "…"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("table lacks %q:\n%s", want, rendered)
		}
	}
}

func TestDescribeExpiry(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)

	cases := map[string]time.Time{
		"never":              {},
		"2028-01-01":         time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		"expired 2025-01-01": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for want, expires := range cases {
		if got := describeExpiry(expires, now); got != want {
			t.Errorf("describeExpiry(%v) = %q, want %q", expires, got, want)
		}
	}
}

func TestDescribeOwnertrustPrefersTrustDB(t *testing.T) {
	fpr := strings.Repeat("B", 40)
	key := gpg.Key{KeyMaterial: gpg.KeyMaterial{Fingerprint: fpr}, OwnerTrust: "u"}
	listingOnly := &keyring{}
	fromTrustDB := &keyring{ownertrust: map[string]gpg.Ownertrust{fpr: gpg.OwnertrustMarginal}}

	if got := listingOnly.describeOwnertrust(key); got != "Ultimate" {
		t.Errorf("from listing = %q, want Ultimate", got)
	}
	if got := fromTrustDB.describeOwnertrust(key); got != "Marginal" {
		t.Errorf("from trustdb = %q, want Marginal", got)
	}
}

func TestGroupFingerprintAndNormalizeRoundTrip(t *testing.T) {
	fpr := "D09141350A83FFE70A43614AE25329D07EFB24BC"

	grouped := groupFingerprint(fpr)

	if grouped != "D091 4135 0A83 FFE7 0A43 614A E253 29D0 7EFB 24BC" {
		t.Errorf("grouped = %q", grouped)
	}
	if normalizeFingerprint(" "+strings.ToLower(grouped)+" ") != fpr {
		t.Error("typed grouped lower-case fingerprint not normalized")
	}
}

func TestBuildUserID(t *testing.T) {
	if got := buildUserID("Alice", "", "alice@example.org"); got != "Alice <alice@example.org>" {
		t.Errorf("without comment = %q", got)
	}
	if got := buildUserID("Alice", "work", "alice@example.org"); got != "Alice (work) <alice@example.org>" {
		t.Errorf("with comment = %q", got)
	}
}

func TestUserIDValidators(t *testing.T) {
	rejectedNames := []string{"", "  ", "Al<ice", "Bob (x)", "Eve\u202e"}
	for _, name := range rejectedNames {
		if validateName(name) == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	rejectedEmails := []string{"", "alice", "Alice <a@example.org>", "a b@example.org", "a@exa\nmple.org"}
	for _, email := range rejectedEmails {
		if validateEmail(email) == nil {
			t.Errorf("email %q accepted", email)
		}
	}
	if validateName("Alice Smith") != nil || validateEmail("alice@example.org") != nil || validateComment("") != nil {
		t.Error("valid user ID parts rejected")
	}
}

func TestValidateArmoredBlockDetectsTruncation(t *testing.T) {
	complete := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"
	truncated := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n"

	if err := validateArmoredBlock(complete); err != nil {
		t.Errorf("complete block rejected: %v", err)
	}
	if err := validateArmoredBlock(truncated); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated block err = %v", err)
	}
}

func TestResolvePathExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}

	resolved, err := resolvePath("~/keys/a.asc")

	if err != nil || resolved != filepath.Join(home, "keys", "a.asc") {
		t.Errorf("resolvePath = %q, %v", resolved, err)
	}
	if _, err := resolvePath("   "); err == nil {
		t.Error("blank path accepted")
	}
}

func TestReadKeyFileRejectsDirectories(t *testing.T) {
	if _, err := readKeyFile(t.TempDir()); err == nil {
		t.Error("directory accepted as key file")
	}
}

func TestLoadKeyringMarksSecretKeysAndCaches(t *testing.T) {
	app, out, home := newTestApp(t)
	fpr := gpgtest.GenerateKey(t, app.Runner.Bin(), home, "Own <own@example.org>")
	ctx := context.Background()

	ring, err := app.loadKeyring(ctx)

	if err != nil {
		t.Fatal(err)
	}
	if _, found := ring.find(fpr); !found || !ring.hasSecret[fpr] {
		t.Fatalf("own key missing or not marked secret: %+v", ring)
	}
	if !strings.Contains(out.String(), "--list-secret-keys") {
		t.Errorf("read-only listing command not shown:\n%s", out.String())
	}
	cached, _ := app.loadKeyring(ctx)
	if cached != ring {
		t.Error("second load did not use the session cache")
	}
	app.invalidateKeyring()
	if reloaded, _ := app.loadKeyring(ctx); reloaded == ring {
		t.Error("invalidated cache was reused")
	}
}

func TestLoadKeyringReadsTrustDBWhenConfigured(t *testing.T) {
	app, _, home := newTestApp(t)
	fpr := gpgtest.GenerateKey(t, app.Runner.Bin(), home, "Own <own@example.org>")
	app.Config.OwnertrustFromTrustDB = true

	ring, err := app.loadKeyring(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if got := ring.ownertrust[fpr]; got != gpg.OwnertrustUltimate {
		t.Errorf("own key ownertrust = %v, want Ultimate", got)
	}
}

func TestPreviewImportListsKeysWithoutImporting(t *testing.T) {
	source, _, sourceHome := newTestApp(t)
	fpr := gpgtest.GenerateKey(t, source.Runner.Bin(), sourceHome, "Peer <peer@example.org>")
	exported, err := exec.Command(source.Runner.Bin(), "--homedir", sourceHome, "--batch", "--armor", "--export", "--", fpr).Output()
	if err != nil {
		t.Fatal(err)
	}
	app, out, _ := newTestApp(t)
	ctx := context.Background()

	previewed, err := app.previewImport(ctx, exported)

	if err != nil || len(previewed) != 1 || previewed[0].Fingerprint != fpr {
		t.Fatalf("preview = %+v, %v", previewed, err)
	}
	if !strings.Contains(out.String(), groupFingerprint(fpr)) {
		t.Errorf("preview does not show the full fingerprint:\n%s", out.String())
	}
	ring, err := app.loadKeyring(ctx)
	if err != nil || len(ring.keys) != 0 {
		t.Errorf("preview changed the keyring: %+v, %v", ring, err)
	}
}

func TestPrintImportResultFlagsKeysMissingFromPreview(t *testing.T) {
	previewedFpr := strings.Repeat("A", 40)
	unexpectedFpr := strings.Repeat("C", 40)
	statuses := gpg.Statuses(gpg.ParseStatus([]byte(
		"[GNUPG:] IMPORT_OK 1 " + previewedFpr + "\n" +
			"[GNUPG:] IMPORT_OK 1 " + unexpectedFpr + "\n" +
			"[GNUPG:] IMPORT_RES 2 0 2 0 0 0 0 0 0 0 0 0 0 0 0\n")))
	previewed := []gpg.Key{{KeyMaterial: gpg.KeyMaterial{Fingerprint: previewedFpr}}}
	var out bytes.Buffer
	app := New(Startup{}, &out)

	app.printImportResult(statuses, previewed)

	printed := out.String()
	if strings.Count(printed, "not shown in the preview") != 1 {
		t.Errorf("want exactly one preview warning:\n%s", printed)
	}
	if !strings.Contains(printed, "Processed 2: 2 new") {
		t.Errorf("summary missing:\n%s", printed)
	}
}
