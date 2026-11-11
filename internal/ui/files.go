package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/fetch"
	"github.com/turiya-fps/cryptosis/internal/fsout"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

type filesMenuItem int

const (
	filesEncrypt filesMenuItem = iota
	filesDecrypt
	filesSign
	filesVerify
	filesBack
)

func (a *App) runFiles(ctx context.Context) error {
	for {
		choice, err := a.chooseFilesMenu()
		if errors.Is(err, huh.ErrUserAborted) || choice == filesBack {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.dispatchFiles(ctx, choice); err != nil && !errors.Is(err, errGPGFailed) {
			a.printError(err)
		}
	}
}

func (a *App) chooseFilesMenu() (filesMenuItem, error) {
	var choice filesMenuItem
	menu := huh.NewSelect[filesMenuItem]().
		Title("Files").
		Options(
			huh.NewOption("Encrypt a file", filesEncrypt),
			huh.NewOption("Decrypt a file", filesDecrypt),
			huh.NewOption("Sign a file (detached, cleartext or inline)", filesSign),
			huh.NewOption("Verify a file or signature", filesVerify),
			huh.NewOption("Back", filesBack),
		).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

func (a *App) dispatchFiles(ctx context.Context, choice filesMenuItem) error {
	switch choice {
	case filesEncrypt:
		return a.encryptFile(ctx)
	case filesDecrypt:
		return a.decryptFile(ctx)
	case filesSign:
		return a.signFile(ctx)
	default:
		return a.verifyFile(ctx)
	}
}

func (a *App) encryptFile(ctx context.Context) error {
	input, err := a.askInputPath("File to encrypt")
	if err != nil || input == "" {
		return ignoreAbort(err)
	}
	request, ok, err := a.chooseRecipients(ctx)
	if err != nil || !ok {
		return err
	}
	signFpr, _, err := a.askSignKey(ctx, "Also sign the file?")
	if err != nil {
		return err
	}
	file, err := openInput(input)
	if err != nil {
		return err
	}
	defer file.Close()

	armor := a.Config.ArmorFiles
	output, err := a.askOutputFilePath("Encrypt to", input+armorSuffix(armor))
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	cmd := gpg.EncryptCommand(request.fprs, signFpr, request.trustAlways, armor).WithStdin(file)
	encrypted := func(result gpg.Result) bool { return result.Status.Has("END_ENCRYPTION") }
	_, err = a.runToFile(ctx, cmd, output, encrypted)
	return err
}

func (a *App) decryptFile(ctx context.Context) error {
	input, err := a.askInputPath("File to decrypt (encrypted or inline-signed)")
	if err != nil || input == "" {
		return ignoreAbort(err)
	}
	output, err := a.askOutputFilePath("Decrypt to", suggestStrippedName(input))
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	file, err := openInput(input)
	if err != nil {
		return err
	}
	defer file.Close()

	// gpg never gets --use-embedded-filename: the destination above is the
	// only place plaintext can land, via the temp+rename output.
	cmd := gpg.DecryptCommand().WithStdin(file)
	decrypted := func(result gpg.Result) bool {
		return result.Status.Has("END_DECRYPTION") || result.Status.Has("PLAINTEXT")
	}
	result, err := a.runToFile(ctx, cmd, output, decrypted)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Signatures:")
	a.printSignatures(result.Status)
	return nil
}

func (a *App) signFile(ctx context.Context) error {
	mode, err := a.chooseSignMode()
	if errors.Is(err, errBack) || errors.Is(err, huh.ErrUserAborted) {
		return nil
	}
	if err != nil {
		return err
	}
	input, err := a.askInputPath("File to sign")
	if err != nil || input == "" {
		return ignoreAbort(err)
	}
	signFpr, err := a.pickSigningKey(ctx)
	if errors.Is(err, errBack) || errors.Is(err, huh.ErrUserAborted) {
		return ignoreAbort(err)
	}
	if err != nil {
		return err
	}
	file, err := openInput(input)
	if err != nil {
		return err
	}
	defer file.Close()

	armor := a.Config.ArmorFiles
	output, err := a.askOutputFilePath("Write signature to", input+signSuffix(mode, armor))
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	cmd := gpg.SignCommand(mode, signFpr, armor).WithStdin(file)
	signed := func(result gpg.Result) bool { return result.Status.Has("SIG_CREATED") }
	_, err = a.runToFile(ctx, cmd, output, signed)
	return err
}

func (a *App) chooseSignMode() (gpg.SignMode, error) {
	const backValue gpg.SignMode = -1
	mode := gpg.SignDetached
	menu := huh.NewSelect[gpg.SignMode]().
		Title("Signature kind").
		Options(
			huh.NewOption("Detached: separate .sig file, original untouched", gpg.SignDetached),
			huh.NewOption("Cleartext: readable text plus ASCII signature (.asc)", gpg.SignClearsign),
			huh.NewOption("Inline: original file wrapped in a signed message", gpg.SignInline),
			huh.NewOption("Back", backValue),
		).
		Value(&mode)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return mode, err
	}
	if mode == backValue {
		return mode, errBack
	}
	return mode, nil
}

// verifyFile routes by content: a detached signature file, a cleartext
// message, or the data file whose .sig/.asc sibling holds the signature.
func (a *App) verifyFile(ctx context.Context) error {
	input, err := a.askInputPath("File to verify (the message, or its detached signature)")
	if err != nil || input == "" {
		return ignoreAbort(err)
	}

	switch gpg.DetectArmor(readPrefix(input)) {
	case gpg.ArmorSignedMessage:
		return a.verifyClearsigned(ctx, input)
	case gpg.ArmorMessage:
		fmt.Fprintln(a.out, "This is an encrypted or inline-signed message; use Files → Decrypt a file.")
		fmt.Fprintln(a.out, "Any signature is reported when the content is decrypted.")
		return nil
	case gpg.ArmorSignature:
		return a.verifyDetached(ctx, input, suggestSignedData(input))
	}
	if sibling := findDetachedSignature(input); sibling != "" {
		fmt.Fprintf(a.out, "Using signature file %s\n", sanitize.Line(sibling))
		return a.verifyDetached(ctx, sibling, input)
	}
	fmt.Fprintln(a.out, "No OpenPGP signature found in or next to this file.")
	fmt.Fprintln(a.out, "For a detached signature, name it <file>.sig (or .asc) beside the data file.")
	return nil
}

// verifyDetached runs gpg --verify and reports every signature found.
func (a *App) verifyDetached(ctx context.Context, sigPath, dataPath string) error {
	dataPath, err := a.askDataFile(dataPath)
	if err != nil || dataPath == "" {
		return ignoreAbort(err)
	}
	result, ran, err := a.confirmAndRun(ctx, gpg.VerifyCommand(sigPath, dataPath))
	if err != nil || !ran {
		return err
	}
	fmt.Fprintln(a.out, "Signatures:")
	a.printSignatures(result.Status)
	if result.ExitCode != 0 {
		return errGPGFailed
	}
	return nil
}

// verifyClearsigned checks the cleartext signature and offers to keep the
// extracted message text — with a loud warning when the signature is bad.
func (a *App) verifyClearsigned(ctx context.Context, input string) error {
	data, err := readCappedFile(input, fetch.MaxBytes)
	if err != nil {
		return err
	}
	output, err := a.askOutputFilePath("Save the message text to", suggestStrippedName(input))
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	out, err := fsout.Create(output.dest)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "\nOutput file: %s", sanitize.Line(output.dest))
	cmd := gpg.DecryptCommand().WithStdin(bytes.NewReader(data))
	result, ran, err := a.confirmAndRun(ctx, cmd.WithStdout(out.Writer()))

	if !ran {
		return errors.Join(ignoreAbort(err), out.Abort())
	}
	if err != nil {
		return errors.Join(err, out.Abort())
	}
	fmt.Fprintln(a.out, "Signatures:")
	a.printSignatures(result.Status)

	switch {
	case result.ExitCode == 0:
		if !hasContent(out.Writer()) {
			fmt.Fprintln(a.out, "gpg wrote nothing; no file was created.")
			return errors.Join(errGPGFailed, out.Abort())
		}
		if err := out.Commit(output.overwrite); err != nil {
			return commitError(err, output.dest)
		}
		fmt.Fprintf(a.out, "Wrote %s\n", sanitize.Line(output.dest))
		return nil
	case hasContent(out.Writer()):
		return a.offerExtractedDespiteFailure(out, output)
	default:
		return errors.Join(errGPGFailed, out.Abort())
	}
}

// offerExtractedDespiteFailure asks whether to keep text whose signature did
// not verify; the default is to discard it.
func (a *App) offerExtractedDespiteFailure(out *fsout.File, output outputFile) error {
	keep, err := a.askConfirm("The signature did NOT verify. Save the extracted text anyway?", false)
	if err != nil || !keep {
		fmt.Fprintln(a.out, "Discarded.")
		return errors.Join(ignoreAbort(err), out.Abort())
	}
	if err := out.Commit(output.overwrite); err != nil {
		return commitError(err, output.dest)
	}
	fmt.Fprintf(a.out, "Wrote %s\n", sanitize.Line(output.dest))
	return nil
}

func commitError(err error, dest string) error {
	if errors.Is(err, fsout.ErrExists) {
		return fmt.Errorf("%s appeared meanwhile; not replaced", sanitize.Line(dest))
	}
	return err
}

// askDataFile confirms the file a detached signature belongs to, suggesting
// the signature path without its suffix. Empty accepts the suggestion; empty
// with no suggestion means cancel.
func (a *App) askDataFile(suggested string) (string, error) {
	title := "File the signature belongs to (empty = back)"
	if suggested != "" {
		title = "File the signature belongs to (empty = " + sanitize.Line(suggested) + ")"
	}
	var path string
	if err := a.inputString(title, "The original data the signature was made over.", &path, validatePathOrEmpty); err != nil {
		return "", err
	}
	if path == "" {
		if suggested == "" {
			return "", nil
		}
		path = suggested
	}
	absolute, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(absolute); err != nil {
		return "", fmt.Errorf("read signed file: %w", err)
	}
	return absolute, nil
}

// askInputPath returns an absolute path to an existing regular file, or ""
// when the user went back.
func (a *App) askInputPath(title string) (string, error) {
	var path string
	if err := a.inputString(title+" (empty = back)", "The file to read; ~ is your home directory.", &path, validatePathOrEmpty); err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	absolute, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("read input file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", sanitize.Line(absolute))
	}
	return absolute, nil
}

// askOutputFilePath is askOutputPath for a full suggested path (used when the
// default belongs next to the input file).
func (a *App) askOutputFilePath(title, suggested string) (outputFile, error) {
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

func openInput(path string) (*os.File, error) {
	file, err := os.Open(path) //nolint:gosec // G304: user-verified path, read only
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	return file, nil
}

// readCappedFile reads a regular file of at most maxBytes.
func readCappedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // G304: user-chosen file, read only
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", sanitize.Line(path))
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", sanitize.Line(path), maxBytes)
	}
	return data, nil
}

// readPrefix returns the first bytes of path for armor detection.
func readPrefix(path string) []byte {
	file, err := os.Open(path) //nolint:gosec // G304: read-only sniff of a user-chosen file
	if err != nil {
		return nil
	}
	defer file.Close()
	prefix := make([]byte, 512)
	n, _ := file.Read(prefix)
	return prefix[:n]
}

// findDetachedSignature looks for a signature file beside dataPath: .sig, or
// an .asc that actually is a detached signature (not a cleartext message).
func findDetachedSignature(dataPath string) string {
	for _, candidate := range []string{dataPath + ".sig", dataPath + ".asc"} {
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if strings.HasSuffix(candidate, ".asc") && gpg.DetectArmor(readPrefix(candidate)) != gpg.ArmorSignature {
			continue
		}
		return candidate
	}
	return ""
}

func armorSuffix(armor bool) string {
	if armor {
		return ".asc"
	}
	return ".gpg"
}

func signSuffix(mode gpg.SignMode, armor bool) string {
	switch mode {
	case gpg.SignClearsign:
		return ".asc"
	case gpg.SignDetached:
		if armor {
			return ".sig.asc"
		}
		return ".sig"
	default:
		return armorSuffix(armor)
	}
}

// suggestStrippedName strips .gpg/.asc/.pgp, or appends .out when the file
// has no OpenPGP-looking suffix.
func suggestStrippedName(path string) string {
	base := filepath.Base(path)
	for _, suffix := range []string{".gpg", ".asc", ".pgp"} {
		if trimmed, found := strings.CutSuffix(base, suffix); found && trimmed != "" {
			return filepath.Join(filepath.Dir(path), trimmed)
		}
	}
	return path + ".out"
}

// suggestSignedData strips signature suffixes from a signature file path.
func suggestSignedData(sigPath string) string {
	base := filepath.Base(sigPath)
	for _, suffix := range []string{".sig.asc", ".sig", ".asc"} {
		if trimmed, found := strings.CutSuffix(base, suffix); found && trimmed != "" {
			return filepath.Join(filepath.Dir(sigPath), trimmed)
		}
	}
	return ""
}
