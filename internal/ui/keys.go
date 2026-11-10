package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/gpg"
)

type keysMenuItem int

const (
	keysList keysMenuItem = iota
	keysGenerate
	keysImport
	keysBack
)

type keyAction int

const (
	actionExportPublic keyAction = iota
	actionExportSecret
	actionSetExpiry
	actionSetOwnertrust
	actionGenRevoke
	actionDelete
	actionBack
)

// errGPGFailed marks a gpg run whose failure was already printed.
var errGPGFailed = errors.New("gpg command failed")

func (a *App) runKeys(ctx context.Context) error {
	for {
		choice, err := a.chooseKeysMenu()
		if errors.Is(err, huh.ErrUserAborted) || choice == keysBack {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.dispatchKeys(ctx, choice); err != nil && !errors.Is(err, errGPGFailed) {
			a.printError(err)
		}
	}
}

func (a *App) chooseKeysMenu() (keysMenuItem, error) {
	var choice keysMenuItem
	menu := huh.NewSelect[keysMenuItem]().
		Title("Keys").
		Options(
			huh.NewOption("List and manage keys", keysList),
			huh.NewOption("Generate a new key", keysGenerate),
			huh.NewOption("Import keys (file, paste, HTTPS URL)", keysImport),
			huh.NewOption("Back", keysBack),
		).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

func (a *App) dispatchKeys(ctx context.Context, choice keysMenuItem) error {
	switch choice {
	case keysList:
		return a.browseKeys(ctx)
	case keysGenerate:
		return a.generateKey(ctx)
	case keysImport:
		return a.importKeys(ctx)
	default:
		return nil
	}
}

// loadKeyring returns the cached keyring, listing it from gpg when stale.
func (a *App) loadKeyring(ctx context.Context) (*keyring, error) {
	if a.keyring != nil {
		return a.keyring, nil
	}
	publicKeys, err := a.listKeys(ctx, false)
	if err != nil {
		return nil, err
	}
	secretKeys, err := a.listKeys(ctx, true)
	if err != nil {
		return nil, err
	}
	ring := &keyring{keys: publicKeys, hasSecret: make(map[string]bool, len(secretKeys))}
	for _, key := range secretKeys {
		ring.hasSecret[key.Fingerprint] = true
	}
	if a.Config.OwnertrustFromTrustDB {
		if ring.ownertrust, err = a.readOwnertrust(ctx); err != nil {
			return nil, err
		}
	}
	a.keyring = ring
	return ring, nil
}

// invalidateKeyring drops the cache after any command that may change keys.
func (a *App) invalidateKeyring() { a.keyring = nil }

func (a *App) listKeys(ctx context.Context, secret bool) ([]gpg.Key, error) {
	listing, err := a.runReadOnly(ctx, gpg.ListKeysCommand(secret))
	if err != nil {
		return nil, err
	}
	return gpg.ParseKeys(listing.Stdout)
}

func (a *App) readOwnertrust(ctx context.Context) (map[string]gpg.Ownertrust, error) {
	exported, err := a.runReadOnly(ctx, gpg.ExportOwnertrustCommand())
	if err != nil {
		return nil, err
	}
	return gpg.ParseOwnertrustExport(exported.Stdout), nil
}

// runReadOnly shows and runs a command that cannot change anything, without
// asking for confirmation.
func (a *App) runReadOnly(ctx context.Context, cmd gpg.Command) (gpg.Result, error) {
	fmt.Fprintf(a.out, "%s: %s\n", cmd.Label(), a.Runner.Preview(cmd))
	result, err := a.Runner.Run(ctx, cmd)
	if err != nil {
		return result, err
	}
	if result.ExitCode != 0 {
		a.printGPGFailure(result)
		return result, errGPGFailed
	}
	return result, nil
}

// browseKeys lists keys and opens the chosen one until the user goes back.
func (a *App) browseKeys(ctx context.Context) error {
	for {
		ring, err := a.loadKeyring(ctx)
		if err != nil {
			return err
		}
		renderKeyTable(a.out, ring, time.Now())
		if len(ring.keys) == 0 {
			return nil
		}
		fpr, err := a.pickKey(ring, "Choose a key (type / to filter)")
		if errors.Is(err, huh.ErrUserAborted) || fpr == "" {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.manageKey(ctx, fpr); err != nil {
			return err
		}
	}
}

// pickKey returns the chosen key's fingerprint, or "" for Back.
func (a *App) pickKey(ring *keyring, title string) (string, error) {
	options := make([]huh.Option[string], 0, len(ring.keys)+1)
	for _, key := range ring.keys {
		options = append(options, huh.NewOption(keyPickerLabel(key, ring.hasSecret[key.Fingerprint]), key.Fingerprint))
	}
	options = append(options, huh.NewOption("Back", ""))

	var fpr string
	picker := huh.NewSelect[string]().Title(title).Options(options...).Height(min(len(options)+2, 15)).Value(&fpr)
	err := a.newForm(huh.NewGroup(picker)).Run()
	return fpr, err
}

// manageKey shows one key and runs actions on it until Back or the key is gone.
func (a *App) manageKey(ctx context.Context, fpr string) error {
	for {
		ring, err := a.loadKeyring(ctx)
		if err != nil {
			return err
		}
		key, found := ring.find(fpr)
		if !found {
			return nil
		}
		renderKeyDetail(a.out, ring, key, time.Now())

		hasSecret := ring.hasSecret[fpr]
		action, err := a.chooseKeyAction(hasSecret)
		if errors.Is(err, huh.ErrUserAborted) || action == actionBack {
			return nil
		}
		if err != nil {
			return err
		}
		err = a.runKeyAction(ctx, action, key, hasSecret)
		if err != nil && !errors.Is(err, errGPGFailed) {
			a.printError(err)
		}
	}
}

func (a *App) chooseKeyAction(hasSecret bool) (keyAction, error) {
	options := []huh.Option[keyAction]{huh.NewOption("Export public key", actionExportPublic)}
	if hasSecret {
		options = append(options,
			huh.NewOption("Export secret key", actionExportSecret),
			huh.NewOption("Change expiry", actionSetExpiry),
		)
	}
	options = append(options, huh.NewOption("Set owner trust", actionSetOwnertrust))
	if hasSecret {
		options = append(options,
			huh.NewOption("Create revocation certificate", actionGenRevoke),
			huh.NewOption("Delete secret and public key", actionDelete),
		)
	} else {
		options = append(options, huh.NewOption("Delete public key", actionDelete))
	}
	options = append(options, huh.NewOption("Back", actionBack))

	var action keyAction
	menu := huh.NewSelect[keyAction]().Title("Key actions").Options(options...).Value(&action)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return action, err
}

func (a *App) runKeyAction(ctx context.Context, action keyAction, key gpg.Key, hasSecret bool) error {
	switch action {
	case actionExportPublic:
		return a.exportKey(ctx, key, false)
	case actionExportSecret:
		return a.exportKey(ctx, key, true)
	case actionSetExpiry:
		return a.changeExpiry(ctx, key)
	case actionSetOwnertrust:
		return a.setOwnertrust(ctx, key)
	case actionGenRevoke:
		return a.createRevocationCertificate(ctx, key)
	case actionDelete:
		return a.deleteKey(ctx, key, hasSecret)
	default:
		return nil
	}
}

// confirmTypedFingerprint guards destructive or secret-exposing actions: the
// user must type the full fingerprint (spaces allowed).
func (a *App) confirmTypedFingerprint(warning, fpr string) (bool, error) {
	fmt.Fprintf(a.out, "\n%s\nFingerprint: %s\n\n", warning, groupFingerprint(fpr))
	var typed string
	validate := func(v string) error {
		if v == "" || normalizeFingerprint(v) == fpr {
			return nil
		}
		return errors.New("does not match the fingerprint; leave empty to cancel")
	}
	field := huh.NewInput().Title("Type the full fingerprint to confirm (empty cancels)").Value(&typed).Validate(validate)
	if err := a.newForm(huh.NewGroup(field)).Run(); err != nil {
		return false, err
	}
	confirmed := normalizeFingerprint(typed) == fpr
	if !confirmed {
		fmt.Fprintln(a.out, "Cancelled.")
	}
	return confirmed, nil
}

func normalizeFingerprint(typed string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(typed), " ", ""))
}
