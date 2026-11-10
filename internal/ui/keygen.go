package ui

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

type newKeyRequest struct {
	name    string
	email   string
	comment string
	expiry  string
}

func (a *App) generateKey(ctx context.Context) error {
	request, err := a.askNewKeyDetails()
	if err != nil {
		return ignoreAbort(err)
	}
	uid := buildUserID(request.name, request.comment, request.email)
	fmt.Fprintln(a.out, "\ngpg will ask for a passphrase to protect the new key.")
	result, ran, err := a.confirmAndRun(ctx, gpg.QuickGenerateKeyCommand(uid, a.Config.KeyAlgo, request.expiry))
	if ran {
		a.invalidateKeyring()
	}
	if err != nil || !ran {
		return err
	}
	fpr, created := gpg.PrimaryFingerprint(result.Status)
	if result.ExitCode != 0 || !created {
		return errGPGFailed
	}
	a.printNewKey(ctx, fpr)

	shouldMatchSubkeyExpiry := a.Config.SubkeyExpiryMatchesPrimary && request.expiry != "never"
	if shouldMatchSubkeyExpiry {
		return a.matchSubkeyExpiry(ctx, fpr, request.expiry)
	}
	return nil
}

func (a *App) askNewKeyDetails() (newKeyRequest, error) {
	request := newKeyRequest{expiry: a.Config.KeyExpiry}
	form := a.newForm(huh.NewGroup(
		huh.NewInput().Title("Name").Value(&request.name).Validate(validateName),
		huh.NewInput().Title("Email").Value(&request.email).Validate(validateEmail),
		huh.NewInput().Title("Comment (optional)").Value(&request.comment).Validate(validateComment),
		huh.NewInput().Title(expiryTitle("Expiry", a.Config.KeyExpiry)).Description(expiryDescription(a.Config.KeyExpiry)).Value(&request.expiry).Validate(validateExpiryOrEmpty),
	).Title("New key (" + a.Config.KeyAlgo + ")"))
	err := form.Run()
	request.name = strings.TrimSpace(request.name)
	request.email = strings.TrimSpace(request.email)
	request.comment = strings.TrimSpace(request.comment)
	request.expiry = orDefault(strings.TrimSpace(request.expiry), a.Config.KeyExpiry)
	return request, err
}

// buildUserID formats "Name (Comment) <email>" as gpg does.
func buildUserID(name, comment, email string) string {
	uid := name
	if comment != "" {
		uid += " (" + comment + ")"
	}
	return uid + " <" + email + ">"
}

func validateName(v string) error {
	name := strings.TrimSpace(v)
	if name == "" {
		return errors.New("enter a name")
	}
	return validateUserIDPart(name, "<>()")
}

func validateComment(v string) error {
	return validateUserIDPart(strings.TrimSpace(v), "<>()")
}

func validateEmail(v string) error {
	email := strings.TrimSpace(v)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || address.Name != "" {
		return errors.New("enter a plain address like alice@example.org")
	}
	return validateUserIDPart(email, "<>() ")
}

// validateUserIDPart rejects characters that would break the "Name (Comment)
// <email>" structure or display unsafely.
func validateUserIDPart(part, forbidden string) error {
	if strings.ContainsAny(part, forbidden) {
		return fmt.Errorf("must not contain any of %q", forbidden)
	}
	if strings.ContainsFunc(part, sanitize.IsUnsafeRune) {
		return errors.New("must not contain control or invisible characters")
	}
	return nil
}

func (a *App) printNewKey(ctx context.Context, fpr string) {
	fmt.Fprintf(a.out, "\nCreated key %s\n", groupFingerprint(fpr))
	home, err := a.Runner.HomeDir(ctx)
	if err != nil {
		return
	}
	revocation := filepath.Join(home, "openpgp-revocs.d", fpr+".rev")
	if _, err := os.Stat(revocation); err == nil {
		fmt.Fprintf(a.out, "gpg saved a revocation certificate at %s\n%s\n", sanitize.Line(revocation), revocsNote)
	}
}

// matchSubkeyExpiry gives each new subkey the primary key's expiry (gpg
// leaves the generated encryption subkey without one).
func (a *App) matchSubkeyExpiry(ctx context.Context, fpr, expiry string) error {
	ring, err := a.loadKeyring(ctx)
	if err != nil {
		return err
	}
	key, found := ring.find(fpr)
	if !found {
		return fmt.Errorf("new key %s not found in keyring", fpr)
	}
	fmt.Fprintln(a.out, "\nSetting the subkey expiry to match the primary key (Settings: New encryption subkey expiry).")
	for _, subkey := range key.Subkeys {
		if err := a.runMutation(ctx, gpg.QuickSetExpireCommand(fpr, expiry, subkey.Fingerprint)); err != nil {
			return err
		}
	}
	return nil
}
