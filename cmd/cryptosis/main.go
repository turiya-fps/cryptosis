// Command cryptosis is an interactive, menu-driven front-end for GnuPG.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"

	"github.com/turiya-fps/cryptosis/internal/clipboard"
	"github.com/turiya-fps/cryptosis/internal/config"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
	"github.com/turiya-fps/cryptosis/internal/ui"
)

// version is set at release build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	// Decrypted text can sit in memory; never let a crash write it to a core file.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fail(fmt.Errorf("disable core dumps: %w", err))
	}

	// huh prompts treat EOF as "accept the default", so piped input is unsafe.
	isInteractive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if !isInteractive {
		return fail(errors.New("cryptosis is interactive: run it in a terminal"))
	}

	ctx := context.Background()
	start, err := detectStartup(ctx)
	if err != nil {
		return fail(err)
	}
	manager := clipboard.NewManager()
	defer manager.Flush() // clear anything still pending at exit
	app := ui.New(start, os.Stdout)
	app.SetInput(os.Stdin)
	app.SetClipboard(manager)
	if err := app.Run(ctx); err != nil {
		return fail(err)
	}
	return 0
}

func detectStartup(ctx context.Context) (ui.Startup, error) {
	configPath, err := config.Path()
	if err != nil {
		return ui.Startup{}, err
	}
	// A config that fails checks is an error, never silently replaced by defaults.
	cfg, err := config.Load(configPath)
	if err != nil {
		return ui.Startup{}, fmt.Errorf("load settings: %w", err)
	}

	bin, err := gpg.ResolveBinary(cfg.GPGPath)
	if err != nil {
		return ui.Startup{}, err
	}
	runner, err := gpg.NewRunner(bin, "")
	if err != nil {
		return ui.Startup{}, err
	}
	info, err := runner.Probe(ctx)
	if err != nil {
		return ui.Startup{}, err
	}
	warnings, configCheckErr := runner.ConfigWarnings(ctx, info.Version)

	return ui.Startup{
		AppVersion:     version,
		Runner:         runner,
		GPG:            info,
		ConfigWarnings: warnings,
		ConfigCheckErr: configCheckErr,
		Config:         cfg,
		ConfigPath:     configPath,
	}, nil
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "cryptosis: %s\n", sanitize.Line(err.Error()))
	return 1
}
