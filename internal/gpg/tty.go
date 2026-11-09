package gpg

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/term"
)

// ttyCommand has a fixed path to avoid PATH lookups; present on macOS and Linux.
const ttyCommand = "/usr/bin/tty"

// environWithGPGTTY returns the inherited environment plus GPG_TTY, which
// gpg-agent needs to put a terminal pinentry on the user's terminal.
func environWithGPGTTY() []string {
	env := os.Environ()
	if os.Getenv("GPG_TTY") != "" {
		return env
	}
	if name := terminalName(); name != "" {
		env = append(env, "GPG_TTY="+name)
	}
	return env
}

var terminalName = sync.OnceValue(findTerminalName)

// findTerminalName names the first of stdin/stdout/stderr that is a terminal,
// so a piped stdin still finds the user's tty.
func findTerminalName() string {
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if !term.IsTerminal(int(f.Fd())) {
			continue
		}
		if name := ttyNameFromProc(f); name != "" {
			return name
		}
		if name := ttyNameFromCommand(f); name != "" {
			return name
		}
	}
	return ""
}

// ttyNameFromProc works on Linux without spawning a process.
func ttyNameFromProc(f *os.File) string {
	name, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if err != nil || !strings.HasPrefix(name, "/dev/") {
		return ""
	}
	return name
}

// ttyNameFromCommand avoids cgo ttyname(3) by asking tty(1) about the descriptor.
func ttyNameFromCommand(f *os.File) string {
	cmd := exec.Command(ttyCommand)
	cmd.Stdin = f
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(out))
	if !strings.HasPrefix(name, "/dev/") {
		return ""
	}
	return name
}
