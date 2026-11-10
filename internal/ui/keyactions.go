package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/config"
	"github.com/turiya-fps/cryptosis/internal/fsout"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

const (
	secretExportWarning = "The secret key will be written to a file, protected only by its passphrase."
	secretDeleteWarning = "This permanently deletes the secret key. Without a backup, data encrypted to it can never be decrypted again."
	revocsNote          = "Keep it offline: anyone holding it can revoke your key."
)

func (a *App) exportKey(ctx context.Context, key gpg.Key, secret bool) error {
	if secret {
		confirmed, err := a.confirmTypedFingerprint(secretExportWarning, key.Fingerprint)
		if err != nil || !confirmed {
			return ignoreAbort(err)
		}
	}
	suffix := "-public.asc"
	if secret {
		suffix = "-secret.asc"
	}
	output, err := a.askOutputPath("Export to file", key.KeyID+suffix)
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	exported := func(result gpg.Result) bool { return result.Status.Has("EXPORTED") }
	return a.runToFile(ctx, gpg.ExportCommand([]string{key.Fingerprint}, secret, true), output, exported)
}

func (a *App) changeExpiry(ctx context.Context, key gpg.Key) error {
	subkeyFpr, err := a.chooseExpiryTarget(key)
	if errors.Is(err, errBack) {
		return nil
	}
	if err != nil {
		return ignoreAbort(err)
	}
	expiry := a.Config.KeyExpiry
	description := expiryDescription(a.Config.KeyExpiry) + " Counted from now."
	if err := a.inputString(expiryTitle("New expiry", a.Config.KeyExpiry), description, &expiry, validateExpiryOrEmpty); err != nil {
		return ignoreAbort(err)
	}
	expiry = orDefault(expiry, a.Config.KeyExpiry)
	return a.runMutation(ctx, gpg.QuickSetExpireCommand(key.Fingerprint, expiry, subkeyFpr))
}

// errBack signals that the user chose Back in a sub-menu.
var errBack = errors.New("back")

// chooseExpiryTarget returns "" for the primary key or a subkey fingerprint.
func (a *App) chooseExpiryTarget(key gpg.Key) (string, error) {
	const backValue = "back"
	options := []huh.Option[string]{huh.NewOption("Primary key", "")}
	for _, subkey := range key.Subkeys {
		label := fmt.Sprintf("Subkey %s (%s) %s", sanitize.Line(subkey.AlgoName()), describeCapabilities(subkey.Capabilities, false), subkey.KeyID)
		options = append(options, huh.NewOption(label, subkey.Fingerprint))
	}
	options = append(options, huh.NewOption("Back", backValue))

	var target string
	menu := huh.NewSelect[string]().Title("Change expiry of").Options(options...).Value(&target)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return "", err
	}
	if target == backValue {
		return "", errBack
	}
	return target, nil
}

func (a *App) setOwnertrust(ctx context.Context, key gpg.Key) error {
	trust := gpg.OwnertrustUndefined
	menu := huh.NewSelect[gpg.Ownertrust]().
		Title("How far do you trust this key's owner to verify other people's keys?").
		Options(
			huh.NewOption("Undefined (don't know)", gpg.OwnertrustUndefined),
			huh.NewOption("Never", gpg.OwnertrustNever),
			huh.NewOption("Marginal", gpg.OwnertrustMarginal),
			huh.NewOption("Full", gpg.OwnertrustFull),
			huh.NewOption("Ultimate (only for your own keys)", gpg.OwnertrustUltimate),
		).
		Value(&trust)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return ignoreAbort(err)
	}
	cmd := gpg.ImportOwnertrustCommand(key.Fingerprint, trust)
	if a.GPG.Capabilities.QuickSetOwnertrust {
		cmd = gpg.QuickSetOwnertrustCommand(key.Fingerprint, trust)
	}
	return a.runMutation(ctx, cmd)
}

func (a *App) createRevocationCertificate(ctx context.Context, key gpg.Key) error {
	reason := gpg.RevokeNoReason
	var description string
	reasonField := huh.NewSelect[int]().
		Title("Reason for revocation").
		Options(
			huh.NewOption("No reason specified (prepared in advance)", gpg.RevokeNoReason),
			huh.NewOption("Key has been compromised", gpg.RevokeCompromised),
			huh.NewOption("Key is superseded", gpg.RevokeSuperseded),
			huh.NewOption("Key is no longer used", gpg.RevokeRetired),
		).
		Value(&reason)
	descriptionField := huh.NewInput().
		Title("Description (optional, one line)").
		Value(&description).
		Validate(func(v string) error {
			_, err := gpg.GenRevokeAnswers(gpg.RevokeNoReason, v)
			return err
		})
	if err := a.newForm(huh.NewGroup(reasonField, descriptionField)).Run(); err != nil {
		return ignoreAbort(err)
	}
	cmd, err := gpg.GenRevokeCommand(key.Fingerprint, reason, strings.TrimSpace(description))
	if err != nil {
		return err
	}
	output, err := a.askOutputPath("Save revocation certificate to", key.KeyID+"-revoke.asc")
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	if err := a.runToFile(ctx, cmd, output, func(gpg.Result) bool { return true }); err != nil {
		return err
	}
	fmt.Fprintln(a.out, revocsNote)
	return nil
}

func (a *App) deleteKey(ctx context.Context, key gpg.Key, hasSecret bool) error {
	if hasSecret {
		confirmed, err := a.confirmTypedFingerprint(secretDeleteWarning, key.Fingerprint)
		if err != nil || !confirmed {
			return ignoreAbort(err)
		}
	}
	return a.runMutation(ctx, gpg.DeleteCommand(key.Fingerprint, hasSecret))
}

// runMutation previews, confirms and runs a command that changes the keyring.
func (a *App) runMutation(ctx context.Context, cmd gpg.Command) error {
	result, ran, err := a.confirmAndRun(ctx, cmd)
	if ran {
		a.invalidateKeyring()
	}
	if err != nil || !ran {
		return err
	}
	if result.ExitCode != 0 {
		return errGPGFailed
	}
	fmt.Fprintln(a.out, "Done.")
	return nil
}

type outputFile struct {
	dest      string // "" when the user cancelled
	overwrite bool
}

// askOutputPath asks for a destination file, suggesting one in the current
// directory, and confirms before an existing file is replaced.
func (a *App) askOutputPath(title, suggestedName string) (outputFile, error) {
	suggested := suggestedName
	if cwd, err := os.Getwd(); err == nil {
		suggested = filepath.Join(cwd, suggestedName)
	}
	dest := suggested
	description := "Empty uses " + sanitize.Line(suggested) + "; ~ is your home directory."
	titleWithDefault := title + " (empty = " + sanitize.Line(suggested) + ")"
	if err := a.inputString(titleWithDefault, description, &dest, validatePathOrEmpty); err != nil {
		return outputFile{}, err
	}
	absolute, err := resolvePath(orDefault(dest, suggested))
	if err != nil {
		return outputFile{}, err
	}
	exists, err := fsout.Exists(absolute)
	if err != nil {
		return outputFile{}, err
	}
	if !exists {
		return outputFile{dest: absolute}, nil
	}
	overwrite, err := a.askConfirm(fmt.Sprintf("%s exists. Replace it?", sanitize.Line(absolute)), false)
	if err != nil || !overwrite {
		fmt.Fprintln(a.out, "Cancelled.")
		return outputFile{}, err
	}
	return outputFile{dest: absolute, overwrite: true}, nil
}

// runToFile runs cmd with stdout going to a temp file that replaces the
// destination only if gpg succeeded and wrote something.
func (a *App) runToFile(ctx context.Context, cmd gpg.Command, output outputFile, succeeded func(gpg.Result) bool) error {
	out, err := fsout.Create(output.dest)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "\nOutput file: %s", sanitize.Line(output.dest))
	result, ran, err := a.confirmAndRun(ctx, cmd.WithStdout(out.Writer()))
	if err != nil || !ran || result.ExitCode != 0 {
		return errors.Join(err, out.Abort())
	}
	if !succeeded(result) || !hasContent(out.Writer()) {
		fmt.Fprintln(a.out, "gpg wrote nothing; no file was created.")
		return errors.Join(errGPGFailed, out.Abort())
	}
	if err := out.Commit(output.overwrite); err != nil {
		if errors.Is(err, fsout.ErrExists) {
			return fmt.Errorf("%s appeared meanwhile; not replaced", sanitize.Line(output.dest))
		}
		return err
	}
	fmt.Fprintf(a.out, "Wrote %s\n", sanitize.Line(output.dest))
	return nil
}

func hasContent(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Size() > 0
}

func validatePath(v string) error {
	_, err := resolvePath(v)
	return err
}

func validatePathOrEmpty(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return validatePath(v)
}

// resolvePath expands a leading ~ and makes the path absolute.
func resolvePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("enter a file path")
	}
	if rest, found := strings.CutPrefix(path, "~/"); found {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, rest)
	}
	return filepath.Abs(path)
}

// Empty answers mean "use the default": huh's accessible mode does not show
// or keep a pre-filled input value.
func validateExpiryOrEmpty(v string) error {
	expiry := strings.TrimSpace(v)
	if expiry == "" {
		return nil
	}
	probe := config.Default()
	probe.KeyExpiry = expiry
	return probe.Validate()
}

// Accessible mode prints titles but not descriptions, so the default goes in the title.
func expiryTitle(title, defaultExpiry string) string {
	return title + " (empty = " + defaultExpiry + ")"
}

func expiryDescription(defaultExpiry string) string {
	return "e.g. 2y, 18m, 6w, 30d or never; empty uses " + defaultExpiry + "."
}

// ignoreAbort turns Esc/Ctrl-C in a form into a quiet return to the menu.
func ignoreAbort(err error) error {
	if errors.Is(err, huh.ErrUserAborted) {
		return nil
	}
	return err
}
