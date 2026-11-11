package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/keyserver"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

type keyserverMenuItem int

const (
	ksFetchEmail keyserverMenuItem = iota
	ksFetchFingerprint
	ksSearch
	ksPublish
	ksBack
)

// runKeyserver is the Keyserver / WKD menu: every fetch is previewed with
// show-only and imported through the normal confirm flow; nothing is ever
// imported without the user seeing it.
func (a *App) runKeyserver(ctx context.Context) error {
	for {
		choice, err := a.chooseKeyserverMenu()
		if errors.Is(err, huh.ErrUserAborted) || choice == ksBack {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.dispatchKeyserver(ctx, choice); err != nil && !errors.Is(err, errGPGFailed) {
			a.printError(err)
		}
	}
}

func (a *App) chooseKeyserverMenu() (keyserverMenuItem, error) {
	var choice keyserverMenuItem
	menu := huh.NewSelect[keyserverMenuItem]().
		Title("Keyserver / WKD").
		Description("Keyserver: "+sanitize.Line(a.Config.Keyserver)).
		Options(
			huh.NewOption("Fetch a key by email (WKD, then keyserver)", ksFetchEmail),
			huh.NewOption("Fetch a key by fingerprint or key ID", ksFetchFingerprint),
			huh.NewOption("Search the keyserver", ksSearch),
			huh.NewOption("Publish one of your public keys", ksPublish),
			huh.NewOption("Back", ksBack),
		).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

func (a *App) dispatchKeyserver(ctx context.Context, choice keyserverMenuItem) error {
	switch choice {
	case ksFetchEmail:
		return a.fetchKeyByEmail(ctx)
	case ksFetchFingerprint:
		return a.fetchKeyByFingerprint(ctx, "")
	case ksSearch:
		return a.searchKeyserver(ctx)
	case ksPublish:
		return a.publishKey(ctx)
	default:
		return nil
	}
}

func (a *App) keyserverClient() (*keyserver.Client, error) {
	return keyserver.New(a.Config.Keyserver, nil)
}

func (a *App) fetchKeyByEmail(ctx context.Context) error {
	var email string
	if err := a.inputString("Email address (empty = back)", "The key is looked up via WKD (the recipient's domain) and then the keyserver.", &email, validateEmailOrEmpty); err != nil {
		return ignoreAbort(err)
	}
	if email == "" {
		return nil
	}
	client, err := a.keyserverClient()
	if err != nil {
		return err
	}
	email = strings.TrimSpace(email)
	fmt.Fprintf(a.out, "Looking up %s (WKD, then %s)\n", sanitize.Line(email), sanitize.Line(a.Config.Keyserver))
	lookup, err := client.GetForEmail(ctx, email)
	if lookup.WKDErr != nil {
		fmt.Fprintf(a.out, "WKD lookup failed (%s); asked the keyserver instead.\n", sanitize.Line(lookup.WKDErr.Error()))
	}
	if err != nil {
		return a.keyserverError(err)
	}
	if lookup.ViaWKD {
		fmt.Fprintln(a.out, "The address's own domain publishes this key (WKD).")
	} else {
		fmt.Fprintln(a.out, "Found on the keyserver. Many keyservers accept any key for any address; confirm the fingerprint with its owner before trusting it.")
	}
	// Per the WKD draft, a client must keep only the user ID it asked for.
	lower := strings.ToLower(email)
	return a.previewAndImport(ctx, lookup.Data, importCheck{keepEmail: lower, wantEmail: lower})
}

func (a *App) fetchKeyByFingerprint(ctx context.Context, preset string) error {
	query := preset
	if preset == "" {
		if err := a.inputString("Fingerprint or key ID (empty = back)", "A full fingerprint or the last 16 hex characters.", &query, validateFprOrKeyIDOrEmpty); err != nil {
			return ignoreAbort(err)
		}
		if query == "" {
			return nil
		}
	}
	query = strings.ToUpper(strings.TrimSpace(query))
	client, err := a.keyserverClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Fetching key %s from %s\n", groupFingerprint(query), sanitize.Line(a.Config.Keyserver))
	data, err := client.GetByFingerprint(ctx, query)
	if err != nil {
		return a.keyserverError(err)
	}
	return a.previewAndImport(ctx, data, importCheck{wantFprSuffix: query})
}

func (a *App) searchKeyserver(ctx context.Context) error {
	var term string
	if err := a.inputString("Search for (empty = back)", "Email address, fingerprint or key ID; some keyservers also match names.", &term, nil); err != nil {
		return ignoreAbort(err)
	}
	if term == "" {
		return nil
	}
	client, err := a.keyserverClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Searching %s\n", sanitize.Line(a.Config.Keyserver))
	results, err := client.Search(ctx, term)
	if err != nil {
		return a.keyserverError(err)
	}
	fpr, err := a.pickSearchResult(results)
	if err != nil || fpr == "" {
		return ignoreAbort(err)
	}
	return a.fetchKeyByFingerprint(ctx, fpr)
}

const maxSearchResults = 30

func (a *App) pickSearchResult(results []keyserver.SearchResult) (string, error) {
	shown := results
	if len(shown) > maxSearchResults {
		shown = shown[:maxSearchResults]
		fmt.Fprintf(a.out, "Showing the first %d of %d results.\n", maxSearchResults, len(results))
	}
	options := make([]huh.Option[string], 0, len(shown)+1)
	for _, result := range shown {
		label := searchResultLabel(result)
		options = append(options, huh.NewOption(label, result.Fingerprint))
	}
	options = append(options, huh.NewOption("Back", ""))
	var fpr string
	picker := huh.NewSelect[string]().Title("Search results").Options(options...).Height(min(len(options)+2, 15)).Value(&fpr)
	if err := a.newForm(huh.NewGroup(picker)).Run(); err != nil {
		return "", err
	}
	return fpr, nil
}

func searchResultLabel(result keyserver.SearchResult) string {
	uid := "(no user ID)"
	if len(result.UIDs) > 0 {
		uid = result.UIDs[0]
		if extra := len(result.UIDs) - 1; extra > 0 {
			uid += fmt.Sprintf(" (+%d more)", extra)
		}
	}
	created := ""
	if result.Created > 0 {
		created = time.Unix(result.Created, 0).UTC().Format("2006-01-02")
	}
	notes := ""
	switch {
	case result.Revoked:
		notes = " [revoked]"
	case result.Expired:
		notes = " [expired]"
	case result.Disabled:
		notes = " [disabled]"
	}
	return fmt.Sprintf("%s  %s  %s%s", groupFingerprint(result.Fingerprint), created, sanitize.Line(uid), notes)
}

// importCheck describes what the fetched material must contain before the
// import confirm is offered.
type importCheck struct {
	wantFprSuffix string // fingerprint or key ID the data must contain
	wantEmail     string // lower-case email a user ID must carry
	keepEmail     string // lower-case email; the import keeps only that user ID
}

func (a *App) previewAndImport(ctx context.Context, data []byte, check importCheck) error {
	preview := gpg.ImportPreviewCommand()
	if check.keepEmail != "" {
		preview = gpg.ImportPreviewKeepUIDCommand(check.keepEmail)
	}
	previewed, err := a.previewImportCommand(ctx, preview, data)
	if err != nil {
		return err
	}
	// keys.openpgp.org serves keys without the user IDs their owners have not
	// verified. Upstream gpg (2.5.24) previews such keys as nothing and
	// refuses them; Debian-patched gpg (2.2.27) previews them, skips them as
	// new keys, and accepts them as updates to keys already held.
	if len(previewed) == 0 {
		return errors.New("the server sent key material gpg cannot import: most likely the key has no user ID. " +
			uidLessHint)
	}
	for _, key := range previewed {
		if len(key.UIDs) == 0 {
			fmt.Fprintf(a.out, "\nNote: key %s has no user ID. gpg skips it unless it only updates a key you already have.\n%s.\n", groupFingerprint(key.Fingerprint), uidLessHint)
		}
	}
	if err := checkImportedKeys(previewed, check); err != nil {
		fmt.Fprintln(a.out, "Refusing to import:")
		return err
	}
	imp := gpg.ImportCommand()
	if check.keepEmail != "" {
		imp = gpg.ImportKeepUIDCommand(check.keepEmail)
	}
	return a.runImportCommand(ctx, imp, data, previewed)
}

const uidLessHint = "keys.openpgp.org hides user IDs until the owner verifies their address; ask the owner to verify it, or get the key from them directly"

// checkImportedKeys verifies the fetched material is what was asked for.
func checkImportedKeys(keys []gpg.Key, check importCheck) error {
	if check.wantFprSuffix != "" {
		for _, key := range keys {
			if strings.HasSuffix(strings.ToUpper(key.Fingerprint), check.wantFprSuffix) {
				return nil
			}
		}
		return fmt.Errorf("none of the returned keys matches %s; the server answered with a different key", groupFingerprint(check.wantFprSuffix))
	}
	if check.wantEmail != "" {
		for _, key := range keys {
			for _, address := range uidEmailAddresses(key.UIDs) {
				if strings.EqualFold(address, check.wantEmail) {
					return nil
				}
			}
		}
		return fmt.Errorf("the returned key has no user ID for %s. keys.openpgp.org hides user IDs until the owner verifies the address; the key may exist but cannot be used here yet", sanitize.Line(check.wantEmail))
	}
	return nil
}

// keyserverError gives common keyserver failures a friendlier shape.
func (a *App) keyserverError(err error) error {
	switch {
	case errors.Is(err, keyserver.ErrNotFound):
		return errors.New("no key found")
	case errors.Is(err, keyserver.ErrNoSearch):
		return fmt.Errorf("%s does not support search; use Fetch by email or fingerprint instead", sanitize.Line(a.Config.Keyserver))
	default:
		return fmt.Errorf("keyserver: %w", err)
	}
}

func validateEmailOrEmpty(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	_, _, err := keyserver.SplitEmail(strings.TrimSpace(v))
	if err != nil {
		return err
	}
	return nil
}

func validateFprOrKeyIDOrEmpty(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	hex := strings.ToUpper(strings.TrimSpace(v))
	if len(hex) != 16 && len(hex) != 40 && len(hex) != 64 {
		return errors.New("enter a full fingerprint or the last 16 hex characters of one")
	}
	for _, r := range hex {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') {
			return errors.New("fingerprints and key IDs are hexadecimal")
		}
	}
	return nil
}

type publishMethod int

const (
	publishSendKeys publishMethod = iota
	publishVKSUpload
	publishBack
)

// publishKey sends one of the local public keys to the keyserver: through
// gpg (dirmngr), or via the VKS upload API with optional email verification.
func (a *App) publishKey(ctx context.Context) error {
	ring, err := a.loadKeyring(ctx)
	if err != nil {
		return err
	}
	fpr, err := a.pickKey(ring, "Publish which public key?")
	if err != nil || fpr == "" {
		return ignoreAbort(err)
	}
	var method publishMethod
	menu := huh.NewSelect[publishMethod]().
		Title("How?").
		Description("Keyserver: "+sanitize.Line(a.Config.Keyserver)).
		Options(
			huh.NewOption(fmt.Sprintf("gpg --send-keys (standard keyserver protocol), via %s", sanitize.Line(a.Config.Keyserver)), publishSendKeys),
			huh.NewOption("VKS upload + email verification (keys.openpgp.org and compatible)", publishVKSUpload),
			huh.NewOption("Back", publishBack),
		).
		Value(&method)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return ignoreAbort(err)
	}
	switch method {
	case publishSendKeys:
		return a.publishSendKeys(ctx, fpr)
	case publishVKSUpload:
		return a.publishVKS(ctx, fpr)
	default:
		return nil
	}
}

func (a *App) publishSendKeys(ctx context.Context, fpr string) error {
	if _, ran, err := a.confirmAndRun(ctx, gpg.SendKeysCommand([]string{fpr}, a.Config.Keyserver)); err != nil || !ran {
		return err
	}
	fmt.Fprintln(a.out, "Sent. Keyservers spread copies between each other; removal is not possible — publish only keys you want public.")
	return nil
}

func (a *App) publishVKS(ctx context.Context, fpr string) error {
	fmt.Fprintln(a.out, "Exporting the public key…")
	exported, err := a.runReadOnly(ctx, gpg.ExportCommand([]string{fpr}, false, true))
	if err != nil {
		return err
	}
	armored := string(exported.Stdout)
	client, err := a.keyserverClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "\nUpload public key\n\n  POST %s (armored public key, %d bytes)\n\n", sanitize.Line(client.URL()+"/vks/v1/upload"), len(armored))
	upload, err := a.askConfirm("Upload the public key to this keyserver?", true)
	if err != nil || !upload {
		return ignoreAbort(err)
	}
	token, err := client.Upload(ctx, armored)
	if err != nil {
		return a.keyserverError(err)
	}
	fmt.Fprintln(a.out, "Uploaded.")
	addresses := uidEmailAddresses(a.findKeyFpr(fpr).UIDs)
	if len(addresses) == 0 {
		fmt.Fprintln(a.out, "The key has no email user IDs, so there is nothing to verify. keys.openpgp.org hides user IDs until their address is verified.")
		return nil
	}
	fmt.Fprintf(a.out, "keys.openpgp.org hides user IDs until their address is verified. Ask it to email a verification link to %s?\n", sanitize.Line(strings.Join(addresses, ", ")))
	verify, err := a.askConfirm("Send the verification emails?", true)
	if err != nil || !verify {
		return ignoreAbort(err)
	}
	if err := client.RequestVerify(ctx, token, addresses); err != nil {
		return a.keyserverError(err)
	}
	fmt.Fprintln(a.out, "Verification emails sent. Follow the link in each mail to publish that address's user ID.")
	return nil
}

// findKeyFpr looks up the keyring entry for fpr without touching the network.
func (a *App) findKeyFpr(fpr string) gpg.Key {
	if a.keyring != nil {
		for _, key := range a.keyring.keys {
			if key.Fingerprint == fpr {
				return key
			}
		}
	}
	return gpg.Key{KeyMaterial: gpg.KeyMaterial{Fingerprint: fpr}}
}

// uidEmailAddresses extracts the addr-spec of each user ID that has one:
// either from the <...> part, or a user ID that is a bare address.
func uidEmailAddresses(uids []gpg.UID) []string {
	var addresses []string
	for _, uid := range uids {
		if start := strings.LastIndex(uid.UserID, "<"); start >= 0 {
			if end := strings.Index(uid.UserID[start:], ">"); end > 0 {
				addresses = append(addresses, uid.UserID[start+1:start+end])
			}
			continue
		}
		if bare := uid.UserID; strings.Contains(bare, "@") && !strings.ContainsAny(bare, " \t") {
			addresses = append(addresses, bare)
		}
	}
	return addresses
}
