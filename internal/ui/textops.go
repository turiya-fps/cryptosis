package ui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"charm.land/huh/v2"

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

type textMenuItem int

const (
	textEncrypt textMenuItem = iota
	textDecrypt
	textBack
)

func (a *App) runText(ctx context.Context) error {
	for {
		choice, err := a.chooseTextMenu()
		if errors.Is(err, huh.ErrUserAborted) || choice == textBack {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.dispatchText(ctx, choice); err != nil && !errors.Is(err, errGPGFailed) {
			a.printError(err)
		}
	}
}

func (a *App) chooseTextMenu() (textMenuItem, error) {
	var choice textMenuItem
	menu := huh.NewSelect[textMenuItem]().
		Title("Text & clipboard").
		Options(
			huh.NewOption("Encrypt text", textEncrypt),
			huh.NewOption("Decrypt text (reports signatures)", textDecrypt),
			huh.NewOption("Back", textBack),
		).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

func (a *App) dispatchText(ctx context.Context, choice textMenuItem) error {
	switch choice {
	case textEncrypt:
		return a.encryptText(ctx)
	default:
		return a.decryptText(ctx)
	}
}

type textSource int

const (
	textFromPaste textSource = iota
	textFromClipboard
	textFromFile
	textFromBack
)

// readText asks where the text comes from and reads it. nil means back.
func (a *App) readText(requireArmored bool) ([]byte, error) {
	options := []huh.Option[textSource]{}
	// Accessible mode reads one line per prompt, so multi-line paste is impossible.
	if !a.Config.AccessibleMode {
		options = append(options, huh.NewOption("Type or paste", textFromPaste))
	}
	if a.clipboard != nil {
		options = append(options, huh.NewOption("Clipboard", textFromClipboard))
	}
	options = append(options, huh.NewOption("File", textFromFile), huh.NewOption("Back", textFromBack))

	source := textFromPaste
	menu := huh.NewSelect[textSource]().Title("Text comes from").Options(options...).Value(&source)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return nil, err
	}

	var data []byte
	var err error
	switch source {
	case textFromPaste:
		data, err = a.readTextPaste(requireArmored)
	case textFromClipboard:
		var text string
		text, err = a.clipboard.Read()
		if err == nil && requireArmored {
			err = validatePGPMessage(text)
		}
		data = []byte(text)
	case textFromFile:
		data, err = a.readTextFile(requireArmored)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		fmt.Fprintln(a.out, "No text.")
		return nil, nil
	}
	return data, nil
}

func (a *App) readTextPaste(requireArmored bool) ([]byte, error) {
	var text string
	field := huh.NewText().
		Title("Text").
		Description(textPasteNote).
		ExternalEditor(false).
		CharLimit(maxPasteChars).
		Lines(12).
		Value(&text)
	if requireArmored {
		field = field.Validate(validatePGPMessage)
	}
	if err := a.newForm(huh.NewGroup(field)).Run(); err != nil {
		return nil, err
	}
	return []byte(text), nil
}

func (a *App) readTextFile(requireArmored bool) ([]byte, error) {
	path, err := a.askInputPath("Text file")
	if err != nil || path == "" {
		return nil, ignoreAbort(err)
	}
	data, err := readCappedFile(path, fetch.MaxBytes)
	if err != nil {
		return nil, err
	}
	if requireArmored && gpg.DetectArmor(data) != gpg.ArmorMessage {
		return nil, errors.New("the file does not contain an ASCII-armored PGP message (-----BEGIN PGP MESSAGE-----)")
	}
	return data, nil
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

func (a *App) encryptText(ctx context.Context) error {
	plaintext, err := a.readText(false)
	if err != nil || plaintext == nil {
		return ignoreAbort(err)
	}
	request, ok, err := a.chooseRecipients(ctx)
	if err != nil || !ok {
		return err
	}
	// Armored always: the result is meant for a message body or the clipboard.
	cmd := gpg.EncryptCommand(request.fprs, "", request.trustAlways, true).WithStdin(bytes.NewReader(plaintext))
	fmt.Fprintln(a.out, "\ngpg will not ask for a passphrase: encryption uses public keys only.")
	result, ran, err := a.confirmAndRun(ctx, cmd)
	if err != nil || !ran {
		return err
	}
	if result.ExitCode != 0 || !result.Status.Has("END_ENCRYPTION") {
		return errGPGFailed
	}
	return a.deliverText(string(result.Stdout), "Encrypted text:")
}

func (a *App) decryptText(ctx context.Context) error {
	ciphertext, err := a.readText(true)
	if err != nil || ciphertext == nil {
		return ignoreAbort(err)
	}
	result, ran, err := a.confirmAndRun(ctx, gpg.DecryptCommand().WithStdin(bytes.NewReader(ciphertext)))
	if err != nil || !ran {
		return err
	}
	if result.ExitCode != 0 || !result.Status.Has("END_DECRYPTION") {
		return errGPGFailed
	}
	fmt.Fprintln(a.out, "Signatures:")
	a.printSignatures(result.Status)
	return a.deliverText(string(result.Stdout), "Decrypted text:")
}

// deliverText hands text to the chosen destination: screen (sanitized, on the
// alternate screen, cleared afterwards), clipboard (with auto-clear), or file.
func (a *App) deliverText(text, label string) error {
	destination, err := a.chooseTextDestination()
	if err != nil || destination == textFromBack {
		return ignoreAbort(err)
	}
	switch destination {
	case textFromClipboard:
		return a.copyToClipboard(text)
	case textFromFile:
		return a.saveTextFile(text)
	default:
		return a.showOnScreen(text, label)
	}
}

func (a *App) chooseTextDestination() (textSource, error) {
	options := []huh.Option[textSource]{huh.NewOption("Show on screen (cleared when you press Enter)", textFromPaste)}
	if a.clipboard != nil {
		options = append(options, huh.NewOption("Copy to clipboard", textFromClipboard))
	}
	options = append(options,
		huh.NewOption("Save to file", textFromFile),
		huh.NewOption("Back", textFromBack))

	destination := textFromPaste
	menu := huh.NewSelect[textSource]().Title("Result goes to").Options(options...).Value(&destination)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return destination, err
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

func (a *App) saveTextFile(text string) error {
	output, err := a.askOutputPath("Save text to", "message.txt")
	if err != nil || output.dest == "" {
		return ignoreAbort(err)
	}
	out, err := fsout.Create(output.dest)
	if err != nil {
		return err
	}
	if _, err := out.Writer().Write([]byte(text)); err != nil {
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
