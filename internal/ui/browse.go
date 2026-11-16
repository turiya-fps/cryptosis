package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/huh/v2"
	"golang.org/x/term"

	"github.com/turiya-fps/cryptosis/internal/dirlist"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

const (
	browseMaxFiles = 500
	browseHeight   = 20
	timeLayout     = "2006-01-02 15:04"
	// Row widths besides the name: huh's border and cursor, type, size,
	// modified, the longest marker, separators; created adds createdWidth.
	browseFixedWidth = 2 + 2 + 2 + 13 + 2 + 5 + 2 + 16 + 2 + 20
	createdWidth     = 2 + 16
	minNameWidth     = 12
	maxNameWidth     = 48
)

// browseColumns is the row layout for the current terminal width.
type browseColumns struct {
	name        int
	showCreated bool // dropped first on narrow terminals
}

// columnsForWidth gives the name what is left after the fixed columns,
// dropping the created column when the name would otherwise get squeezed.
func columnsForWidth(width int) browseColumns {
	nameRoom := width - browseFixedWidth
	if nameRoom-createdWidth >= minNameWidth {
		return browseColumns{name: min(maxNameWidth, nameRoom-createdWidth), showCreated: true}
	}
	return browseColumns{name: max(minNameWidth, min(maxNameWidth, nameRoom))}
}

type browseMode int

const (
	browseEncrypt browseMode = iota
	browseDecrypt
)

type browseAction int

const (
	browseUp browseAction = iota
	browseDir
	browseFile
	browseBack
)

// browseChoice is one picker option's value.
type browseChoice struct {
	action browseAction
	name   string
}

// browsePGPDir lets the user pick a file under the configured PGP directory,
// which is the ceiling: Up there (or Back anywhere) returns "".
func (a *App) browsePGPDir(mode browseMode) (string, error) {
	if a.Config.PGPDir == "" {
		fmt.Fprintln(a.out, "Set Settings → PGP file directory first.")
		return "", nil
	}
	root, err := filepath.EvalSymlinks(a.Config.PGPDir)
	if err != nil {
		return "", fmt.Errorf("PGP file directory: %w", err)
	}
	rel := ""
	var cameFrom string // subdirectory just left, to put the cursor on it
	for {
		listing, err := dirlist.List(filepath.Join(root, rel), browseMaxFiles)
		if err != nil {
			if rel == "" {
				return "", fmt.Errorf("PGP file directory: %w", err)
			}
			a.printError(err)
			rel, cameFrom = parentRel(rel)
			continue
		}
		choice, err := a.chooseBrowseEntry(filepath.Join(root, rel), listing, mode, cameFrom)
		if err != nil {
			return "", ignoreAbort(err)
		}
		switch choice.action {
		case browseFile:
			return filepath.Join(root, rel, choice.name), nil
		case browseDir:
			next := filepath.Join(rel, choice.name)
			if !filepath.IsLocal(next) { // names come from ReadDir; defence in depth
				return "", fmt.Errorf("refusing path outside the PGP directory: %s", sanitize.Line(next))
			}
			rel, cameFrom = next, ""
		case browseUp:
			if rel == "" {
				return "", nil
			}
			rel, cameFrom = parentRel(rel)
		default:
			return "", nil
		}
	}
}

// parentRel returns the parent of rel ("" is the root) and rel's last element.
func parentRel(rel string) (parent, child string) {
	parent = filepath.Dir(rel)
	if parent == "." {
		parent = ""
	}
	return parent, filepath.Base(rel)
}

func (a *App) chooseBrowseEntry(dir string, listing dirlist.Listing, mode browseMode, cameFrom string) (browseChoice, error) {
	columns := columnsForWidth(terminalWidth())
	disabled := map[string]string{}
	options := []huh.Option[browseChoice]{huh.NewOption("↑ Up", browseChoice{action: browseUp})}
	for _, entry := range listing.Entries {
		if entry.Kind == dirlist.Dir {
			label := "▸ " + truncateRunes(sanitize.Line(entry.Name), columns.name) + "/"
			options = append(options, huh.NewOption(label, browseChoice{browseDir, entry.Name}))
			continue
		}
		label, reason := formatBrowseRow(entry, columns, mode)
		if reason != "" {
			disabled[entry.Name] = reason
		}
		options = append(options, huh.NewOption(label, browseChoice{browseFile, entry.Name}))
	}
	options = append(options, huh.NewOption("Back", browseChoice{action: browseBack}))

	description := browseHeader(columns)
	if listing.Truncated {
		description += fmt.Sprintf("\nShowing the %d newest files only.", browseMaxFiles)
	}
	choice := browseChoice{action: browseUp}
	if cameFrom != "" {
		choice = browseChoice{browseDir, cameFrom}
	}
	title := abbreviateHome(dir)
	if a.Config.AccessibleMode { // huh's accessible select prints the title only
		title += "\n" + description
	}
	menu := huh.NewSelect[browseChoice]().
		Title(title).
		Description(description).
		Options(options...).
		Height(min(len(options)+4, browseHeight)).
		Validate(rejectDisabled(disabled)).
		Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

// rejectDisabled stands in for disabled options, which huh lacks: choosing a
// file listed in disabled shows its reason and keeps the picker open.
func rejectDisabled(disabled map[string]string) func(browseChoice) error {
	return func(c browseChoice) error {
		if reason, found := disabled[c.name]; found && c.action == browseFile {
			return errors.New(reason)
		}
		return nil
	}
}

// formatBrowseRow renders a file as fixed columns and returns why it cannot
// be chosen in this mode ("" = selectable).
func formatBrowseRow(entry dirlist.Entry, columns browseColumns, mode browseMode) (label, disabledReason string) {
	name := truncateRunes(sanitize.Line(entry.Name), columns.name)
	row := fmt.Sprintf("%s  %-13s  %5s  %-16s",
		padRunes(name, columns.name), kindLabel(entry.Kind), humanSize(entry.Size), formatTime(entry.Modified))
	if columns.showCreated {
		row += fmt.Sprintf("  %-16s", formatTime(entry.Created))
	}

	encrypted := entry.Kind == dirlist.ArmoredMessage || entry.Kind == dirlist.BinaryEncrypted
	var marker string
	switch {
	case entry.Kind == dirlist.Unreadable:
		marker, disabledReason = "✗ unreadable", "This file cannot be read (check its permissions)."
	case mode == browseEncrypt && encrypted:
		marker = "[encrypted]"
	case mode == browseDecrypt && entry.Kind == dirlist.BinaryEncrypted:
		marker, disabledReason = "✗ binary: Files menu", "Binary (unarmored) message: decrypt it with Files → Decrypt."
	case mode == browseDecrypt && entry.Kind != dirlist.ArmoredMessage:
		marker, disabledReason = "✗ not encrypted", "Not an encrypted PGP message."
	}
	if marker != "" {
		row += "  " + marker
	}
	return strings.TrimRight(row, " "), disabledReason
}

func browseHeader(columns browseColumns) string {
	header := fmt.Sprintf("  %s  %-13s  %5s  %-16s", padRunes("NAME", columns.name), "TYPE", "SIZE", "MODIFIED")
	if columns.showCreated {
		header += "  CREATED"
	}
	return strings.TrimRight(header, " ")
}

func kindLabel(kind dirlist.Kind) string {
	switch kind {
	case dirlist.ArmoredMessage:
		return "PGP message"
	case dirlist.BinaryEncrypted:
		return "PGP msg (bin)"
	case dirlist.Signature:
		return "PGP signature"
	case dirlist.Key:
		return "PGP key"
	case dirlist.OpenPGPOther:
		return "OpenPGP (bin)"
	case dirlist.Text:
		return "text"
	case dirlist.Binary:
		return "binary"
	case dirlist.Dir:
		return "directory"
	default:
		return "unreadable"
	}
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%dB", size)
	}
	value := float64(size)
	for _, suffix := range []string{"K", "M", "G", "T"} {
		value /= unit
		if value < unit || suffix == "T" {
			if value < 10 {
				return fmt.Sprintf("%.1f%s", value, suffix)
			}
			return fmt.Sprintf("%.0f%s", value, suffix)
		}
	}
	return "" // unreachable
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.Local().Format(timeLayout)
}

func padRunes(s string, width int) string {
	if pad := width - len([]rune(s)); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// terminalWidth is stdout's width, 80 columns if unknown.
func terminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

// abbreviateHome shows a path with ~ for the home directory, sanitized.
func abbreviateHome(path string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, found := strings.CutPrefix(path, home); found && (rest == "" || rest[0] == filepath.Separator) {
			path = "~" + rest
		}
	}
	return sanitize.Line(path)
}
