package ui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/dirlist"
	"github.com/turiya-fps/cryptosis/internal/fetch"
	"github.com/turiya-fps/cryptosis/internal/fsout"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

const (
	// maxPasteChars keeps huh's textarea responsive; bigger input must come
	// from the clipboard or a file.
	maxPasteChars = 100_000
	textPasteNote = "Text is piped to gpg; nothing is written to disk. Over ~99 lines or 100k characters, use clipboard or file input."
)

type cryptMenuItem int

const (
	cryptEncrypt cryptMenuItem = iota
	cryptDecrypt
	cryptBack
)

func (a *App) runCrypt(ctx context.Context) error {
	for {
		choice, err := a.chooseCryptMenu()
		if errors.Is(err, huh.ErrUserAborted) || choice == cryptBack {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.dispatchCrypt(ctx, choice); err != nil && !errors.Is(err, errGPGFailed) {
			a.printError(err)
		}
	}
}

func (a *App) chooseCryptMenu() (cryptMenuItem, error) {
	var choice cryptMenuItem
	menu := huh.NewSelect[cryptMenuItem]().
		Title("Encrypt & decrypt").
		Options(
			huh.NewOption("Encrypt", cryptEncrypt),
			huh.NewOption("Decrypt (reports signatures)", cryptDecrypt),
			huh.NewOption("Back", cryptBack),
		).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

func (a *App) dispatchCrypt(ctx context.Context, choice cryptMenuItem) error {
	switch choice {
	case cryptEncrypt:
		return a.encrypt(ctx)
	default:
		return a.decrypt(ctx)
	}
}

type inputSource int

const (
	sourcePaste inputSource = iota
	sourceClipboard
	sourceFile
	sourceBrowse
	sourceBack
)

// input is what gpg reads: bytes in memory, or a file over fetch.MaxBytes
// that is streamed instead.
type input struct {
	data  []byte   // paste, clipboard, or a file of at most fetch.MaxBytes
	path  string   // the file chosen; "" for paste and clipboard
	large *os.File // set instead of data for a file over fetch.MaxBytes
}

func (in input) close() {
	if in.large != nil {
		_ = in.large.Close()
	}
}

// chooseInput asks where the input comes from and reads it; ok is false when
// the user went back. Decrypting typed or clipboard text requires an armored
// message; files may hold anything gpg decrypts (binary, inline-signed).
func (a *App) chooseInput(decrypt bool) (in input, ok bool, err error) {
	options := []huh.Option[inputSource]{}
	// Accessible mode reads one line per prompt, so multi-line paste is impossible.
	if !a.Config.AccessibleMode {
		options = append(options, huh.NewOption("Type or paste", sourcePaste))
	}
	if a.clipboard != nil {
		options = append(options, huh.NewOption("Clipboard", sourceClipboard))
	}
	browseLabel := "Browse PGP directory (not set)"
	if a.Config.PGPDir != "" {
		browseLabel = "Browse " + abbreviateHome(a.Config.PGPDir)
	}
	options = append(options,
		huh.NewOption("File", sourceFile),
		huh.NewOption(browseLabel, sourceBrowse),
		huh.NewOption("Back", sourceBack))

	for {
		source := sourcePaste
		menu := huh.NewSelect[inputSource]().Title("Input from").Options(options...).Value(&source)
		if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
			return input{}, false, err
		}
		switch source {
		case sourcePaste:
			in.data, err = a.readPaste(decrypt)
		case sourceClipboard:
			var text string
			text, err = a.clipboard.Read()
			if err == nil && decrypt {
				err = validatePGPMessage(text)
			}
			in.data = []byte(text)
		case sourceFile:
			in, ok, err = a.readTypedFile(decrypt)
			if err == nil && !ok {
				return input{}, false, nil
			}
		case sourceBrowse:
			in, ok, err = a.readBrowsedFile(decrypt)
			if err == nil && !ok {
				continue // back to "Input from"
			}
		default:
			return input{}, false, nil
		}
		if err != nil {
			return input{}, false, err
		}
		if in.large == nil && len(in.data) == 0 {
			fmt.Fprintln(a.out, "The input is empty.")
			return input{}, false, nil
		}
		return in, true, nil
	}
}

func (a *App) readPaste(decrypt bool) ([]byte, error) {
	var text string
	field := huh.NewText().
		Title("Text").
		Description(textPasteNote).
		ExternalEditor(false).
		CharLimit(maxPasteChars).
		Lines(12).
		Value(&text)
	if decrypt {
		field = field.Validate(validatePGPMessage)
	}
	if err := a.newForm(huh.NewGroup(field)).Run(); err != nil {
		return nil, err
	}
	return []byte(text), nil
}

func (a *App) readTypedFile(decrypt bool) (input, bool, error) {
	title := "File to encrypt"
	if decrypt {
		title = "File to decrypt (encrypted or inline-signed)"
	}
	path, err := a.askInputPath(title)
	if err != nil || path == "" {
		return input{}, false, ignoreAbort(err)
	}
	// A typed path may be a symlink; open its target without following
	// further links, and keep the typed path for output suggestions.
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return input{}, false, fmt.Errorf("read input file: %w", err)
	}
	in, err := openFileInput(target, fetch.MaxBytes)
	in.path = path
	return in, err == nil, err
}

// readBrowsedFile reads a file picked under the PGP directory; ok is false
// when the user left the browser without choosing one.
func (a *App) readBrowsedFile(decrypt bool) (input, bool, error) {
	mode := browseEncrypt
	if decrypt {
		mode = browseDecrypt
	}
	path, err := a.browsePGPDir(mode)
	if err != nil || path == "" {
		return input{}, false, err
	}
	in, err := openFileInput(path, fetch.MaxBytes)
	return in, err == nil, err
}

// openFileInput reads path into memory, or leaves it open for streaming when
// it is over maxBytes. The size check and the read use the same open file.
func openFileInput(path string, maxBytes int64) (input, error) {
	file, info, err := dirlist.Open(path)
	if err != nil {
		return input{}, err
	}
	if info.Size() > maxBytes {
		return input{path: path, large: file}, nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return input{}, err
	}
	if int64(len(data)) > maxBytes {
		return input{}, fmt.Errorf("%s grew while being read; try again", sanitize.Line(path))
	}
	return input{data: data, path: path}, nil
}

// validatePGPMessage guards against huh's textarea silently dropping text
// after 99 lines: a paste must carry the armor END line.
func validatePGPMessage(v string) error {
	if gpg.DetectArmor([]byte(v)) != gpg.ArmorMessage {
		return errors.New("no -----BEGIN PGP MESSAGE----- block found")
	}
	if !strings.Contains(v, "-----END PGP MESSAGE-----") {
		return errors.New("no -----END PGP MESSAGE----- line; the paste looks truncated — use clipboard or file input")
	}
	return nil
}

func (a *App) encrypt(ctx context.Context) error {
	in, ok, err := a.chooseInput(false)
	if err != nil || !ok {
		return ignoreAbort(err)
	}
	defer in.close()
	request, ok, err := a.chooseRecipients(ctx)
	if err != nil || !ok {
		return err
	}
	signFpr, _, err := a.askSignKey(ctx, "Also sign?")
	if err != nil {
		return err
	}
	// Text input is always armored: the result is meant for a message body
	// or the clipboard. Files follow the armor setting.
	armor := in.path == "" || a.Config.ArmorFiles
	job := cryptJob{
		cmd:       gpg.EncryptCommand(request.fprs, signFpr, request.trustAlways, armor),
		succeeded: func(result gpg.Result) bool { return result.Status.Has("END_ENCRYPTION") },
		outTitle:  "Encrypt to",
		label:     "Encrypted:",
	}
	if in.path != "" {
		job.suggested = in.path + armorSuffix(armor)
	}
	if signFpr == "" {
		fmt.Fprintln(a.out, "\ngpg will not ask for a passphrase: encryption uses public keys only.")
	}
	return a.runJob(ctx, in, job)
}

func (a *App) decrypt(ctx context.Context) error {
	in, ok, err := a.chooseInput(true)
	if err != nil || !ok {
		return ignoreAbort(err)
	}
	defer in.close()
	// gpg never gets --use-embedded-filename: plaintext lands only where the
	// user chooses, through deliverResult or the temp+rename output.
	job := cryptJob{
		cmd: gpg.DecryptCommand(),
		// PLAINTEXT without END_DECRYPTION: an inline-signed, unencrypted message.
		succeeded: func(result gpg.Result) bool {
			return result.Status.Has("END_DECRYPTION") || result.Status.Has("PLAINTEXT")
		},
		outTitle: "Decrypt to",
		label:    "Decrypted:",
		after: func(result gpg.Result) {
			fmt.Fprintln(a.out, "Signatures:")
			a.reportSignatures(ctx, result.Status)
		},
	}
	if in.path != "" {
		job.suggested = suggestStrippedName(in.path)
	}
	return a.runJob(ctx, in, job)
}

// cryptJob is one encrypt or decrypt run, independent of the input source.
type cryptJob struct {
	cmd       gpg.Command
	succeeded func(gpg.Result) bool
	outTitle  string           // output path prompt for streamed input
	suggested string           // output next to the input file; "" for text input
	label     string           // heading for the screen view
	after     func(gpg.Result) // runs once gpg succeeded, before delivery
}

// runJob captures gpg's output in memory and offers it to deliverResult; a
// large file input streams to an output file chosen up front instead.
func (a *App) runJob(ctx context.Context, in input, job cryptJob) error {
	if in.large != nil {
		return a.streamJob(ctx, in.large, job)
	}
	result, ran, err := a.confirmAndRun(ctx, job.cmd.WithStdin(bytes.NewReader(in.data)))
	if err != nil || !ran {
		return err
	}
	if result.ExitCode != 0 || !job.succeeded(result) {
		return errGPGFailed
	}
	job.done(result)
	return a.deliverResult(result.Stdout, job.label, job.suggested)
}

func (a *App) streamJob(ctx context.Context, file *os.File, job cryptJob) error {
	output, err := a.askOutputFilePath(job.outTitle, job.suggested)
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	result, err := a.runToFile(ctx, job.cmd.WithStdin(file), output, job.succeeded)
	if err != nil {
		return err
	}
	job.done(result)
	return nil
}

func (j cryptJob) done(result gpg.Result) {
	if j.after != nil {
		j.after(result)
	}
}

type destination int

const (
	destScreen destination = iota
	destClipboard
	destFile
	destBack
)

// resultDestinations lists where a result can go, default first: a file
// first when there is a path next to the input; screen and clipboard only
// for text.
func resultDestinations(isText, nextToInput, hasClipboard bool) []destination {
	var dests []destination
	if nextToInput {
		dests = append(dests, destFile)
	}
	if isText {
		dests = append(dests, destScreen)
		if hasClipboard {
			dests = append(dests, destClipboard)
		}
	}
	if !nextToInput {
		dests = append(dests, destFile)
	}
	return append(dests, destBack)
}

// deliverResult hands gpg's output to the chosen destination: screen
// (sanitized, on the alternate screen, cleared afterwards), clipboard (with
// auto-clear), or a file (suggested next to the input file, if any).
func (a *App) deliverResult(data []byte, label, suggested string) error {
	isText := dirlist.IsText(data)
	if !isText {
		fmt.Fprintln(a.out, "The result is binary, so it can only be saved to a file.")
	}
	labels := map[destination]string{
		destScreen:    "Show on screen (cleared when you press Enter)",
		destClipboard: "Copy to clipboard",
		destFile:      "Save to file",
		destBack:      "Back",
	}
	dests := resultDestinations(isText, suggested != "", a.clipboard != nil)
	options := make([]huh.Option[destination], 0, len(dests))
	for _, dest := range dests {
		options = append(options, huh.NewOption(labels[dest], dest))
	}
	choice := dests[0]
	menu := huh.NewSelect[destination]().Title("Result goes to").Options(options...).Value(&choice)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return ignoreAbort(err)
	}
	switch choice {
	case destScreen:
		return a.showOnScreen(string(data), label)
	case destClipboard:
		return a.copyToClipboard(string(data))
	case destFile:
		return a.saveResult(data, suggested)
	default:
		return nil
	}
}

func (a *App) copyToClipboard(text string) error {
	clearAfter := time.Duration(a.Config.ClipboardClearSeconds) * time.Second
	if err := a.clipboard.Set(text, clearAfter); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Copied to clipboard.")
	if a.Config.ClipboardClearSeconds > 0 {
		fmt.Fprintf(a.out, "It will be cleared after %d seconds (Settings), unless replaced meanwhile.\n", a.Config.ClipboardClearSeconds)
	} else {
		fmt.Fprintln(a.out, "Clipboard auto-clear is off (Settings).")
	}
	if runtime.GOOS == "darwin" {
		fmt.Fprintln(a.out, "Note: macOS Universal Clipboard may share this with nearby Apple devices.")
	}
	fmt.Fprintln(a.out, "Clipboard history tools (e.g. clipboard managers) may keep a copy regardless.")
	return nil
}

// saveResult writes data via temp+rename, suggesting a path next to the
// input file, else message.txt in the PGP directory or the current one.
func (a *App) saveResult(data []byte, suggested string) error {
	var output outputFile
	var err error
	switch {
	case suggested != "":
		output, err = a.askOutputFilePath("Save to", suggested)
	case a.Config.PGPDir != "":
		output, err = a.askOutputFilePath("Save to", filepath.Join(a.Config.PGPDir, "message.txt"))
	default:
		output, err = a.askOutputPath("Save to", "message.txt")
	}
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	out, err := fsout.Create(output.dest)
	if err != nil {
		return err
	}
	if _, err := out.Writer().Write(data); err != nil {
		return errors.Join(err, out.Abort())
	}
	if err := out.Commit(output.overwrite); err != nil {
		return commitError(err, output.dest)
	}
	fmt.Fprintf(a.out, "Wrote %s\n", sanitize.Line(output.dest))
	return nil
}

// showOnScreen displays text on the alternate screen buffer and clears it
// when the user presses Enter, so plaintext does not stay in the scrollback.
// Control and invisible characters are stripped for display; save to a file
// for the exact bytes.
func (a *App) showOnScreen(text, label string) error {
	if a.in == nil {
		fmt.Fprintf(a.out, "\n%s\n%s\n", label, sanitize.Text(text))
		fmt.Fprintln(a.out, "(no input available; text not cleared — prefer a file destination)")
		return nil
	}
	fmt.Fprint(a.out, "\x1b[?1049h\x1b[H\x1b[2J") // alternate screen, cleared
	fmt.Fprintf(a.out, "%s\n\n%s\n", sanitize.Line(label), sanitize.Text(text))
	fmt.Fprint(a.out, "\n[sanitized view; control characters removed — press Enter to clear]")

	reader := bufio.NewReader(a.in)
	_, _ = reader.ReadString('\n')

	fmt.Fprint(a.out, "\x1b[?1049l\x1b[H\x1b[2J") // back to the main screen, cleared
	return nil
}
