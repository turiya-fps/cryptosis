package ui

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/config"
	"github.com/turiya-fps/cryptosis/internal/gpg"
)

func validKey(fpr, validity string) gpg.Key {
	return gpg.Key{
		KeyMaterial: gpg.KeyMaterial{
			Fingerprint:  fpr,
			KeyID:        fpr[len(fpr)-16:],
			Validity:     validity,
			Capabilities: "scESC",
		},
		UIDs: []gpg.UID{{UserID: "Owner <owner@example.org>"}},
	}
}

func repeatRune(r rune) string { return strings.Repeat(string(r), 40) }

func withEncryptionSubkey(key gpg.Key) gpg.Key {
	key.Subkeys = []gpg.KeyMaterial{{
		Fingerprint: repeatRune('S'), KeyID: strings.Repeat("S", 16), Capabilities: "e",
	}}
	return key
}

func TestClassifyRecipient(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-24 * time.Hour)
	future := now.Add(365 * 24 * time.Hour)

	fpr := repeatRune
	_ = fpr

	cases := []struct {
		name   string
		key    gpg.Key
		want   recipientStatus
		reason string
	}{
		{"full validity with encryption subkey", withEncryptionSubkey(validKey(fpr('A'), "f")), recipientOK, ""},
		{"ultimate with encrypting primary", func() gpg.Key {
			key := validKey(fpr('B'), "u")
			key.Capabilities = "sceSC"
			return key
		}(), recipientOK, ""},
		{"marginal", withEncryptionSubkey(validKey(fpr('C'), "m")), recipientOK, ""},
		{"unverified dash", withEncryptionSubkey(validKey(fpr('D'), "-")), recipientUnverified, ""},
		{"unverified none", withEncryptionSubkey(validKey(fpr('E'), "n")), recipientUnverified, ""},
		{"revoked", withEncryptionSubkey(validKey(fpr('F'), "r")), recipientBlocked, "revoked"},
		{"expired validity", withEncryptionSubkey(validKey(fpr('G'), "e")), recipientBlocked, "expired"},
		{"disabled", withEncryptionSubkey(validKey(fpr('H'), "d")), recipientBlocked, "disabled"},
		{"no encryption capability", func() gpg.Key {
			key := validKey(fpr('I'), "f")
			key.Capabilities = "sc"
			return key
		}(), recipientBlocked, "no usable encryption (sub)key"},
		{"uppercase E only is not the primary's own capability", validKey(fpr('M'), "f"), recipientBlocked, "no usable encryption (sub)key"},
		{"primary expired by date", func() gpg.Key {
			key := withEncryptionSubkey(validKey(fpr('J'), "f"))
			key.Expires = expired
			return key
		}(), recipientBlocked, "expired"},
		{"only subkey expired", func() gpg.Key {
			key := withEncryptionSubkey(validKey(fpr('K'), "f"))
			key.Subkeys[0].Expires = expired
			return key
		}(), recipientBlocked, "no usable encryption (sub)key"},
		{"subkey expires later", func() gpg.Key {
			key := withEncryptionSubkey(validKey(fpr('L'), "f"))
			key.Subkeys[0].Expires = future
			return key
		}(), recipientOK, ""},
	}
	for _, testCase := range cases {
		classified := classifyRecipient(testCase.key, now)
		if classified.status != testCase.want {
			t.Errorf("%s: status = %v, want %v (reason %q)", testCase.name, classified.status, testCase.want, classified.reason)
		}
		if classified.status == recipientBlocked && classified.reason != testCase.reason {
			t.Errorf("%s: reason = %q, want %q", testCase.name, classified.reason, testCase.reason)
		}
	}
}

func TestWeakAlgoNote(t *testing.T) {
	rsa2048 := gpg.Key{KeyMaterial: gpg.KeyMaterial{Algo: 1, Length: 2048}}
	rsa4096 := gpg.Key{KeyMaterial: gpg.KeyMaterial{Algo: 1, Length: 4096}}
	dsa := gpg.Key{KeyMaterial: gpg.KeyMaterial{Algo: 17, Length: 1024}}

	if weakAlgoNote(rsa2048) == "" || weakAlgoNote(dsa) == "" {
		t.Error("weak algorithms not tagged")
	}
	if weakAlgoNote(rsa4096) != "" {
		t.Error("RSA-4096 tagged weak")
	}
}

func TestResolveUnverifiedRefusesWithoutSetting(t *testing.T) {
	app, out, _ := newTestApp(t)
	app.Config = config.Default() // AllowUnverifiedRecipients off
	unverified := classifyRecipient(withEncryptionSubkey(validKey(strings.Repeat("D", 40), "-")), time.Now())
	if unverified.status != recipientUnverified {
		t.Fatalf("classification = %v", unverified.status)
	}

	request, ok, err := app.resolveUnverified([]recipient{unverified})

	if err != nil || ok || len(request.fprs) != 0 {
		t.Fatalf("ok=%v err=%v request=%+v, want refusal", ok, err, request)
	}
	printed := out.String()
	if !strings.Contains(printed, "no assurance") || !strings.Contains(printed, "Allow unverified recipients") {
		t.Errorf("refusal message incomplete:\n%s", printed)
	}
}

func TestRecipientPickerRejectsEmptySelection(t *testing.T) {
	var selected []string
	picker := newRecipientPicker([]huh.Option[string]{huh.NewOption("Alice", "FPR-A")}, &selected)
	picker.WithKeyMap(huh.NewDefaultKeyMap()) // normally set by the form
	picker.Focus()
	enter := tea.KeyPressMsg{Code: tea.KeyEnter}

	if _, cmd := picker.Update(enter); cmd != nil || !errors.Is(picker.Error(), errNoRecipient) {
		t.Fatalf("Enter with nothing marked: cmd=%v err=%v, want blocked with errNoRecipient", cmd, picker.Error())
	}

	picker.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if _, cmd := picker.Update(enter); cmd == nil || picker.Error() != nil {
		t.Fatalf("Enter after marking: cmd=%v err=%v, want submit", cmd, picker.Error())
	}
	if len(selected) != 1 || selected[0] != "FPR-A" {
		t.Errorf("selected = %v, want [FPR-A]", selected)
	}
}

func TestSuggestNames(t *testing.T) {
	cases := map[string]string{
		"/docs/report.txt.gpg": "/docs/report.txt",
		"/docs/report.gpg":     "/docs/report",
		"/docs/message.asc":    "/docs/message",
		"/docs/data.pgp":       "/docs/data",
		"/docs/plain.txt":      "/docs/plain.txt.out",
	}
	for input, want := range cases {
		if got := suggestStrippedName(input); got != want {
			t.Errorf("suggestStrippedName(%q) = %q, want %q", input, got, want)
		}
	}
	sigCases := map[string]string{
		"/docs/report.txt.sig":     "/docs/report.txt",
		"/docs/report.txt.sig.asc": "/docs/report.txt",
		"/docs/message.asc":        "/docs/message",
		"/docs/sigonly":            "",
	}
	for input, want := range sigCases {
		if got := suggestSignedData(input); got != want {
			t.Errorf("suggestSignedData(%q) = %q, want %q", input, got, want)
		}
	}
	if got := signSuffix(gpg.SignDetached, true); got != ".sig.asc" {
		t.Errorf("detached armored suffix = %q", got)
	}
	if got := signSuffix(gpg.SignClearsign, false); got != ".asc" {
		t.Errorf("clearsign suffix = %q", got)
	}
}

func TestFindDetachedSignature(t *testing.T) {
	dir := t.TempDir()
	writeForTest(t, dir+"/report.txt", "data")
	writeForTest(t, dir+"/report.txt.sig", "binary signature bytes")

	if got := findDetachedSignature(dir + "/report.txt"); got != dir+"/report.txt.sig" {
		t.Errorf("sig = %q", got)
	}
	if got := findDetachedSignature(dir + "/missing.txt"); got != "" {
		t.Errorf("missing sig = %q", got)
	}

	// An .asc sibling must actually be a detached signature, not a clearsigned message.
	writeForTest(t, dir+"/notes.txt", "data")
	writeForTest(t, dir+"/notes.txt.asc", "-----BEGIN PGP SIGNED MESSAGE-----\n")
	if got := findDetachedSignature(dir + "/notes.txt"); got != "" {
		t.Errorf("clearsigned .asc used as detached signature: %q", got)
	}
	writeForTest(t, dir+"/notes.txt.asc", "-----BEGIN PGP SIGNATURE-----\n")
	if got := findDetachedSignature(dir + "/notes.txt"); got != dir+"/notes.txt.asc" {
		t.Errorf("armored detached sig = %q", got)
	}

	// cryptosis names armored detached signatures <file>.sig.asc.
	writeForTest(t, dir+"/plan.txt", "data")
	writeForTest(t, dir+"/plan.txt.sig.asc", "-----BEGIN PGP SIGNED MESSAGE-----\n")
	if got := findDetachedSignature(dir + "/plan.txt"); got != "" {
		t.Errorf("clearsigned .sig.asc used as detached signature: %q", got)
	}
	writeForTest(t, dir+"/plan.txt.sig.asc", "-----BEGIN PGP SIGNATURE-----\n")
	if got := findDetachedSignature(dir + "/plan.txt"); got != dir+"/plan.txt.sig.asc" {
		t.Errorf(".sig.asc sig = %q", got)
	}
}

func TestClassifyVerifyInput(t *testing.T) {
	cases := map[string]verifyRoute{
		"-----BEGIN PGP SIGNED MESSAGE-----\n":    routeClearsigned,
		"-----BEGIN PGP SIGNATURE-----\n":         routeDetached,
		"-----BEGIN PGP MESSAGE-----\n":           routeMessage,
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n":  routeKey,
		"-----BEGIN PGP PRIVATE KEY BLOCK-----\n": routeKey,
		"\x89\x01\x33\x04":                        routeDetached, // binary detached signature
		"\xa3\x01":                                routeMessage,  // binary signed (compressed)
		"\x90\x0d\x03":                            routeMessage,  // binary signed (one-pass)
		"\x84\x5e\x03":                            routeMessage,  // binary encrypted
		"\x99\x01\x0d\x04":                        routeKey,      // binary public key
		"plain text\n":                            routeData,
		"":                                        routeData,
	}
	for prefix, want := range cases {
		if got := classifyVerifyInput([]byte(prefix)); got != want {
			t.Errorf("classifyVerifyInput(%q) = %v, want %v", prefix, got, want)
		}
	}
}

func TestReadPrefixReportsUnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads any file")
	}
	path := t.TempDir() + "/locked"
	writeForTest(t, path, "-----BEGIN PGP SIGNATURE-----\n")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrefix(path); err == nil {
		t.Fatal("unreadable file read without error")
	}
	if prefix, err := readPrefix(t.TempDir() + "/missing"); err == nil {
		t.Fatalf("missing file read: %q", prefix)
	}
}

func TestFileAccessHint(t *testing.T) {
	eperm := &fs.PathError{Op: "open", Path: "/Users/x/Downloads/f", Err: syscall.EPERM}
	if fileAccessHint("darwin", fmt.Errorf("read input: %w", eperm)) == "" {
		t.Error("no hint for wrapped EPERM on darwin")
	}
	for name, hint := range map[string]string{
		"linux EPERM":   fileAccessHint("linux", eperm),
		"darwin EACCES": fileAccessHint("darwin", &fs.PathError{Op: "open", Path: "f", Err: syscall.EACCES}),
		"darwin other":  fileAccessHint("darwin", errors.New("operation not permitted")),
	} {
		if hint != "" {
			t.Errorf("%s: unexpected hint %q", name, hint)
		}
	}
}

func TestValidatePGPMessage(t *testing.T) {
	complete := "-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n"
	truncated := "-----BEGIN PGP MESSAGE-----\n\nabc\n"

	if err := validatePGPMessage(complete); err != nil {
		t.Errorf("complete message rejected: %v", err)
	}
	if err := validatePGPMessage(truncated); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated message err = %v", err)
	}
	if err := validatePGPMessage("just text"); err == nil {
		t.Error("unarmored text accepted as message")
	}
}

func TestPrintSignaturesCoversAllOutcomes(t *testing.T) {
	statuses := gpg.Statuses(gpg.ParseStatus([]byte(
		"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG AAAABBBBCCCCDDDD Alice <alice@example.org>\n" +
			"[GNUPG:] VALIDSIG " + strings.Repeat("A", 40) + " 2026-11-10 1778714400\n[GNUPG:] TRUST_FULLY\n" +
			"[GNUPG:] NEWSIG\n[GNUPG:] BADSIG DEADBEEFDEADBEEF Mallory <mallory@example.org>\n" +
			"[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG " + strings.Repeat("C", 16) + " 22 10 00 1778714400 9\n")))
	var out bytes.Buffer
	app := New(Startup{}, &out)

	app.printSignatures(statuses)

	printed := out.String()
	for _, want := range []string{
		"Good signature by Alice <alice@example.org>",
		"trust: full, made 2026-11-10",
		"BAD signature claiming Mallory",
		"not in your keyring",
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("output lacks %q:\n%s", want, printed)
		}
	}
	if !strings.Contains(printed, groupFingerprint(strings.Repeat("A", 40))) {
		t.Errorf("good signature lacks full fingerprint:\n%s", printed)
	}
}

func TestShowOnScreenClearsAfterEnter(t *testing.T) {
	var out bytes.Buffer
	app := New(Startup{Config: config.Default()}, &out)
	app.SetInput(strings.NewReader("\n"))

	hostile := "plain\x1b[31mtext\x1b[0m and a bidi\u202eoverride"
	if err := app.showOnScreen(hostile, "Decrypted text:"); err != nil {
		t.Fatal(err)
	}

	shown := out.String()
	// Hostile sequences from the text must be gone; the constant alt-screen
	// controls are ours and remain.
	if strings.Contains(shown, "\x1b[31m") || strings.Contains(shown, "\x1b[0m") {
		t.Errorf("escape sequence not stripped: %q", shown)
	}
	if strings.Contains(shown, "\u202e") {
		t.Errorf("bidi override not stripped: %q", shown)
	}
	// The enter/leave sequences are ours (constant), so they survive sanitization.
	if !strings.Contains(shown, "\x1b[?1049h") || !strings.Contains(shown, "\x1b[?1049l") {
		t.Error("alternate screen not entered and left")
	}
	if !strings.HasSuffix(strings.TrimRight(shown, "\n"), "\x1b[H\x1b[2J") {
		t.Errorf("main screen not cleared on return: %q", shown[len(shown)-20:])
	}
}

func writeForTest(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
