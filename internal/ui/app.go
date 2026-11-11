// Package ui is the interactive front-end: short-lived huh forms in a loop,
// with gpg run between forms so pinentry gets a clean terminal.
//
// Untrusted text (user IDs, gpg output, config values) is printed only through
// sanitize, and never placed in huh Note descriptions, which interpret markdown.
package ui

import (
	"context"
	"errors"
	"fmt"
	"io"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/clipboard"
	"github.com/turiya-fps/cryptosis/internal/config"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

// Startup is everything detected before the menu opens.
type Startup struct {
	AppVersion     string
	Runner         *gpg.Runner
	GPG            gpg.Info
	ConfigWarnings []gpg.ConfigWarning
	ConfigCheckErr error // gpg.conf could not be checked
	Config         config.Config
	ConfigPath     string
}

// App holds UI state for one session.
type App struct {
	Startup
	out       io.Writer
	in        io.Reader          // terminal input for the plaintext viewer
	clipboard *clipboard.Manager // nil when clipboard support is unavailable
	keyring   *keyring           // session cache; nil until listed or after a change
}

// New returns an App writing to out.
func New(startup Startup, out io.Writer) *App {
	return &App{Startup: startup, out: out}
}

// SetInput sets the reader used for full-screen prompts (the main terminal).
func (a *App) SetInput(in io.Reader) { a.in = in }

// SetClipboard enables clipboard input and output.
func (a *App) SetClipboard(manager *clipboard.Manager) { a.clipboard = manager }

type menuItem int

const (
	menuKeys menuItem = iota
	menuFiles
	menuText
	menuKeyserver
	menuGPGInfo
	menuSettings
	menuQuit
)

// Run shows the banner and the main menu until the user quits.
func (a *App) Run(ctx context.Context) error {
	a.printBanner()
	for {
		choice, err := a.chooseMainMenu()
		if errors.Is(err, huh.ErrUserAborted) || choice == menuQuit {
			return nil
		}
		if err != nil {
			return err
		}
		if err := a.dispatch(ctx, choice); err != nil {
			a.printError(err)
		}
	}
}

func (a *App) chooseMainMenu() (menuItem, error) {
	var choice menuItem
	menu := huh.NewSelect[menuItem]().
		Title("cryptosis").
		Options(
			huh.NewOption("Keys", menuKeys),
			huh.NewOption("Files: encrypt, decrypt, sign, verify", menuFiles),
			huh.NewOption("Text & clipboard", menuText),
			huh.NewOption("Keyserver / WKD", menuKeyserver),
			huh.NewOption("gpg version", menuGPGInfo),
			huh.NewOption("Settings", menuSettings),
			huh.NewOption("Quit", menuQuit),
		).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

func (a *App) dispatch(ctx context.Context, choice menuItem) error {
	switch choice {
	case menuKeys:
		return a.runKeys(ctx)
	case menuFiles:
		return a.runFiles(ctx)
	case menuText:
		return a.runText(ctx)
	case menuGPGInfo:
		return a.showGPGVersion(ctx)
	case menuSettings:
		return a.runSettings()
	default:
		fmt.Fprintln(a.out, "Not implemented yet.")
		return nil
	}
}

func (a *App) showGPGVersion(ctx context.Context) error {
	result, ran, err := a.confirmAndRun(ctx, gpg.VersionCommand())
	if err != nil || !ran {
		return err
	}
	fmt.Fprintln(a.out, sanitize.Text(string(result.Stdout)))
	return nil
}

func (a *App) printBanner() {
	fmt.Fprintf(a.out, "cryptosis %s\n", a.AppVersion)
	fmt.Fprintf(a.out, "gpg:    %s (%s)\n", sanitize.Line(a.GPG.Bin), a.GPG.Version)
	fmt.Fprintf(a.out, "config: %s\n", sanitize.Line(a.ConfigPath))
	if a.ConfigCheckErr != nil {
		fmt.Fprintf(a.out, "warning: could not check gpg.conf: %s\n", sanitize.Line(a.ConfigCheckErr.Error()))
	}
	for _, warning := range a.ConfigWarnings {
		fmt.Fprintf(a.out, "warning: %s sets %q: %s\n",
			sanitize.Line(warning.File), sanitize.Line(warning.Option), warning.Risk)
	}
	fmt.Fprintln(a.out)
}

func (a *App) printError(err error) {
	fmt.Fprintf(a.out, "error: %s\n\n", sanitize.Line(err.Error()))
}

func (a *App) newForm(groups ...*huh.Group) *huh.Form {
	return huh.NewForm(groups...).WithAccessible(a.Config.AccessibleMode)
}
