package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/fetch"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

type importSource int

const (
	importFromFile importSource = iota
	importFromPaste
	importFromURL
	importBack
)

// Paste goes through huh's textarea, which silently stops at 99 lines; the
// armor END check turns that into a visible error.
const pasteDescription = "Paste an ASCII-armored key block. Long keys (over ~99 lines) must be imported from a file or URL."

// importKeys reads key data once, previews it with show-only, then imports
// exactly the same bytes.
func (a *App) importKeys(ctx context.Context) error {
	data, err := a.readImportData(ctx)
	if err != nil || data == nil {
		return ignoreAbort(err)
	}
	previewed, err := a.previewImport(ctx, data)
	if err != nil || len(previewed) == 0 {
		return err
	}
	return a.runImport(ctx, data, previewed)
}

// readImportData returns nil data when the user went back.
func (a *App) readImportData(ctx context.Context) ([]byte, error) {
	// Accessible mode reads one line per prompt, so a key block cannot be pasted.
	options := []huh.Option[importSource]{huh.NewOption("File", importFromFile)}
	if !a.Config.AccessibleMode {
		options = append(options, huh.NewOption("Paste", importFromPaste))
	}
	options = append(options, huh.NewOption("HTTPS URL", importFromURL), huh.NewOption("Back", importBack))

	source := importFromFile
	menu := huh.NewSelect[importSource]().Title("Import keys from").Options(options...).Value(&source)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return nil, err
	}
	switch source {
	case importFromFile:
		return a.readImportFile()
	case importFromPaste:
		return a.readImportPaste()
	case importFromURL:
		return a.readImportURL(ctx)
	default:
		return nil, nil
	}
}

func (a *App) readImportFile() ([]byte, error) {
	var path string
	if err := a.inputString("Key file (empty = back)", "Armored (.asc) or binary (.gpg) key file; ~ is your home directory.", &path, validatePathOrEmpty); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	absolute, err := resolvePath(path)
	if err != nil {
		return nil, err
	}
	return readCappedFile(absolute, fetch.MaxBytes)
}

func (a *App) readImportPaste() ([]byte, error) {
	var pasted string
	field := huh.NewText().
		Title("Key block").
		Description(pasteDescription).
		ExternalEditor(false).
		Lines(10).
		Value(&pasted).
		Validate(validateArmoredBlock)
	if err := a.newForm(huh.NewGroup(field)).Run(); err != nil {
		return nil, err
	}
	return []byte(pasted), nil
}

func validateArmoredBlock(v string) error {
	begin := strings.Index(v, "-----BEGIN PGP ")
	end := strings.LastIndex(v, "-----END PGP ")
	if begin < 0 {
		return errors.New("no -----BEGIN PGP ... line found")
	}
	if end < begin {
		return errors.New("no -----END PGP ... line found; the paste may be truncated, import from a file instead")
	}
	return nil
}

func (a *App) readImportURL(ctx context.Context) ([]byte, error) {
	var rawURL string
	validate := func(v string) error {
		if strings.TrimSpace(v) == "" {
			return nil
		}
		_, err := fetch.ValidateURL(strings.TrimSpace(v))
		return err
	}
	if err := a.inputString("Key URL (https only; empty = back)", "The download is previewed before anything is imported.", &rawURL, validate); err != nil {
		return nil, err
	}
	if rawURL == "" {
		return nil, nil
	}
	fmt.Fprintf(a.out, "Downloading %s\n", sanitize.Line(rawURL))
	return fetch.New(nil).Get(ctx, rawURL)
}

// previewImport lists what the data would import without touching the keyring.
func (a *App) previewImport(ctx context.Context, data []byte) ([]gpg.Key, error) {
	return a.previewImportCommand(ctx, gpg.ImportPreviewCommand(), data)
}

// previewImportCommand is previewImport with the import command chosen by the
// caller (e.g. a keep-uid variant); the command must be a show-only import.
func (a *App) previewImportCommand(ctx context.Context, cmd gpg.Command, data []byte) ([]gpg.Key, error) {
	preview, err := a.runReadOnly(ctx, cmd.WithStdin(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	keys, err := gpg.ParseKeys(preview.Stdout)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		fmt.Fprintln(a.out, "No OpenPGP keys found in the data.")
		return nil, nil
	}
	previewRing := &keyring{keys: keys, hasSecret: make(map[string]bool)}
	for _, key := range keys {
		previewRing.hasSecret[key.Fingerprint] = key.Secret
	}
	fmt.Fprintln(a.out, "\nKeys in the data:")
	renderKeyTable(a.out, previewRing, time.Now())
	for _, key := range keys {
		fmt.Fprintf(a.out, "  %s  %s\n", groupFingerprint(key.Fingerprint), primaryUserID(key))
	}
	if containsSecretKey(keys) {
		fmt.Fprintln(a.out, "\nWarning: the data contains SECRET keys.")
	}
	return keys, nil
}

func containsSecretKey(keys []gpg.Key) bool {
	for _, key := range keys {
		if key.Secret {
			return true
		}
	}
	return false
}

func (a *App) runImport(ctx context.Context, data []byte, previewed []gpg.Key) error {
	return a.runImportCommand(ctx, gpg.ImportCommand(), data, previewed)
}

// runImportCommand is runImport with the import command chosen by the caller.
func (a *App) runImportCommand(ctx context.Context, cmd gpg.Command, data []byte, previewed []gpg.Key) error {
	result, ran, err := a.confirmAndRun(ctx, cmd.WithStdin(bytes.NewReader(data)))
	if ran {
		a.invalidateKeyring()
	}
	if err != nil || !ran {
		return err
	}
	if result.ExitCode != 0 {
		return errGPGFailed
	}
	a.printImportResult(result.Status, previewed)
	return nil
}

func (a *App) printImportResult(statuses gpg.Statuses, previewed []gpg.Key) {
	previewedFprs := make(map[string]bool, len(previewed))
	for _, key := range previewed {
		previewedFprs[key.Fingerprint] = true
	}
	for _, line := range statuses {
		if line.Keyword != "IMPORT_OK" || len(line.Args) < 2 {
			continue
		}
		flags, _ := strconv.Atoi(line.Args[0])
		fpr := sanitize.Line(line.Args[1])
		fmt.Fprintf(a.out, "  %s: %s\n", groupFingerprint(fpr), gpg.ImportOKReason(flags))
		if !previewedFprs[fpr] {
			fmt.Fprintln(a.out, "  Warning: this key was not shown in the preview.")
		}
	}
	summary, found := gpg.ParseImportSummary(statuses)
	if !found {
		return
	}
	fmt.Fprintf(a.out, "Processed %d: %d new, %d unchanged, %d new user IDs, %d new subkeys, %d new signatures, %d revocations",
		summary.Count, summary.Imported, summary.Unchanged, summary.NewUIDs, summary.NewSubkeys, summary.NewSignatures, summary.NewRevocations)
	if summary.SecretRead > 0 {
		fmt.Fprintf(a.out, ", %d of %d secret keys imported", summary.SecretImported, summary.SecretRead)
	}
	if summary.NotImported > 0 {
		fmt.Fprintf(a.out, ", %d not imported", summary.NotImported)
	}
	if summary.NoUserID > 0 {
		fmt.Fprintf(a.out, ", %d skipped (no user ID)", summary.NoUserID)
	}
	fmt.Fprintln(a.out)
}
