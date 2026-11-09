package gpg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

// MinVersion is the oldest supported gpg: 2.2.17 added --locate-external-keys
// and the signature-spoofing fixes cryptosis relies on.
var MinVersion = Version{Major: 2, Minor: 2, Patch: 17}

// Version is a gpg release number.
type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AtLeast reports whether v >= other.
func (v Version) AtLeast(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch >= other.Patch
}

// ParseVersion reads the first line of `gpg --version`, e.g. "gpg (GnuPG) 2.4.4"
// or "gpg (GnuPG/MacGPG2) 2.2.41". Suffixes like "-beta" or "+git" are ignored.
func ParseVersion(output []byte) (Version, error) {
	firstLine, _, _ := bytes.Cut(output, []byte("\n"))
	fields := strings.Fields(string(firstLine))
	if len(fields) < 3 || fields[0] != "gpg" || !strings.HasPrefix(fields[1], "(GnuPG") {
		return Version{}, fmt.Errorf("unrecognised gpg version line %q", firstLine)
	}
	parts := strings.SplitN(fields[len(fields)-1], ".", 3)
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("unrecognised gpg version %q", fields[len(fields)-1])
	}
	numbers := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(leadingDigits(part))
		if err != nil {
			return Version{}, fmt.Errorf("unrecognised gpg version %q", fields[len(fields)-1])
		}
		numbers[i] = n
	}
	return Version{Major: numbers[0], Minor: numbers[1], Patch: numbers[2]}, nil
}

func leadingDigits(s string) string {
	end := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if end == -1 {
		return s
	}
	return s[:end]
}

// Capabilities are optional gpg features, detected from --dump-options rather
// than inferred from version numbers.
type Capabilities struct {
	QuickSetOwnertrust bool
}

// ParseCapabilities reads `gpg --dump-options` output (one option per line).
func ParseCapabilities(dumpOptions []byte) Capabilities {
	options := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(dumpOptions))
	for scanner.Scan() {
		options[strings.TrimSpace(scanner.Text())] = true
	}
	return Capabilities{QuickSetOwnertrust: options["--quick-set-ownertrust"]}
}

// Info describes the gpg installation cryptosis is driving.
type Info struct {
	Bin          string
	Version      Version
	Capabilities Capabilities
}

// Probe runs read-only gpg commands to detect version and capabilities, and
// rejects versions older than MinVersion.
func (r *Runner) Probe(ctx context.Context) (Info, error) {
	versionResult, err := r.runRequiringSuccess(ctx, VersionCommand())
	if err != nil {
		return Info{}, err
	}
	version, err := ParseVersion(versionResult.Stdout)
	if err != nil {
		return Info{}, err
	}
	if !version.AtLeast(MinVersion) {
		return Info{}, fmt.Errorf("gpg %s is too old; cryptosis needs %s or newer", version, MinVersion)
	}

	optionsResult, err := r.runRequiringSuccess(ctx, DumpOptionsCommand())
	if err != nil {
		return Info{}, err
	}
	return Info{Bin: r.bin, Version: version, Capabilities: ParseCapabilities(optionsResult.Stdout)}, nil
}

func (r *Runner) runRequiringSuccess(ctx context.Context, c Command) (Result, error) {
	result, err := r.Run(ctx, c)
	if err != nil {
		return result, err
	}
	if !result.Succeeded() {
		return result, fmt.Errorf("%s: gpg exited with code %d", c.Label(), result.ExitCode)
	}
	return result, nil
}
