package ui

import (
	"context"
	"errors"
	"fmt"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

// confirmAndRun prints the exact gpg command, asks for confirmation (default
// No) and runs it. ran is false when the user declined.
func (a *App) confirmAndRun(ctx context.Context, cmd gpg.Command) (result gpg.Result, ran bool, err error) {
	a.printPreview(cmd)

	confirmed, err := a.askConfirm("Run this command?", false)
	if errors.Is(err, huh.ErrUserAborted) || (err == nil && !confirmed) {
		fmt.Fprintln(a.out, "Cancelled.")
		return gpg.Result{}, false, nil
	}
	if err != nil {
		return gpg.Result{}, false, err
	}

	result, err = a.Runner.Run(ctx, cmd)
	if err != nil {
		return result, true, err
	}
	if result.ExitCode != 0 {
		a.printGPGFailure(result)
	}
	return result, true, nil
}

// printPreview writes the command as plain text: huh would wrap or restyle it.
// QuoteArgv output is terminal-safe and pastes back into a shell unchanged.
func (a *App) printPreview(cmd gpg.Command) {
	fmt.Fprintf(a.out, "\n%s\n\n  %s\n\n", cmd.Label(), a.Runner.Preview(cmd))
	hasConfigWarnings := len(a.ConfigWarnings) > 0
	if hasConfigWarnings {
		fmt.Fprintln(a.out, "Note: your gpg.conf settings shown at startup also apply.")
	}
}

func (a *App) printGPGFailure(result gpg.Result) {
	fmt.Fprintf(a.out, "gpg failed (exit code %d)\n", result.ExitCode)
	if len(result.Stderr) > 0 {
		fmt.Fprintln(a.out, sanitize.Text(string(result.Stderr)))
	}
}

func (a *App) askConfirm(title string, defaultValue bool) (bool, error) {
	confirmed := defaultValue
	field := huh.NewConfirm().Title(title).Affirmative("Yes").Negative("No").Value(&confirmed)
	err := a.newForm(huh.NewGroup(field)).Run()
	return confirmed, err
}
