// Package gpg runs the system gpg binary with typed commands and parses its
// machine-readable output. It never invokes a shell.
package gpg

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	maxStatusLineBytes     = 64 << 10
	maxStatusBytes         = 16 << 20
	maxColonLineBytes      = 1 << 20
	maxStderrBytes         = 1 << 20
	maxCapturedStdoutBytes = 64 << 20

	// gpg may leave helpers (e.g. a freshly started gpg-agent) holding our pipes.
	statusDrainTimeout = 2 * time.Second
	pipeWaitDelay      = 5 * time.Second

	statusFD = "3" // first entry of exec.Cmd.ExtraFiles
)

// ErrOutputTooLarge is returned when gpg output exceeds a capture limit.
var ErrOutputTooLarge = errors.New("gpg output exceeds size limit")

// Command is a typed gpg invocation. Commands are built only by constructors in
// this package, so callers cannot pass arbitrary arguments to gpg.
type Command struct {
	label    string
	options  []string
	operands []string  // placed after "--"
	stdin    io.Reader // nil means /dev/null
	stdout   io.Writer // nil means captured into Result.Stdout
	// answers, when set, runs the command without --batch but with --no-tty
	// and --command-fd: gpg prompts arrive as GET_* status lines and are
	// answered from this script. Only GenRevokeCommand sets it.
	answers []PromptAnswer
}

// Answers returns the scripted prompt answers (empty for ordinary commands).
func (c Command) Answers() []PromptAnswer { return c.answers }

// Label is a short human description of the command.
func (c Command) Label() string { return c.label }

// WithStdin returns a copy of c that feeds r to gpg's stdin.
func (c Command) WithStdin(r io.Reader) Command {
	c.stdin = r
	return c
}

// WithStdout returns a copy of c that streams gpg's stdout to w instead of capturing it.
func (c Command) WithStdout(w io.Writer) Command {
	c.stdout = w
	return c
}

// Result is the outcome of a gpg invocation that started.
type Result struct {
	ExitCode int
	Status   Statuses
	Stdout   []byte // only when the command had no stdout writer
	Stderr   []byte // untrusted: sanitize before display
}

// Succeeded reports exit code 0 and the presence of every required status keyword.
// gpg's exit code alone is not a reliable success signal.
func (r Result) Succeeded(requiredKeywords ...string) bool {
	if r.ExitCode != 0 {
		return false
	}
	for _, keyword := range requiredKeywords {
		if !r.Status.Has(keyword) {
			return false
		}
	}
	return true
}

// Runner executes Commands against one gpg binary and optional home directory.
type Runner struct {
	bin     string
	homedir string

	homeOnce sync.Once
	homeDir  string
	homeErr  error
}

// PrimaryFingerprint returns the primary key fingerprint from a KEY_CREATED
// status line. gpg prints one line with type B (primary and subkey created
// together, as --quick-generate-key does) or a first line with type P.
func PrimaryFingerprint(statuses Statuses) (string, bool) {
	for _, line := range statuses {
		if line.Keyword != "KEY_CREATED" || len(line.Args) < 2 {
			continue
		}
		if line.Args[0] == "P" || line.Args[0] == "B" {
			return line.Args[1], true
		}
	}
	return "", false
}

// NewRunner validates bin (absolute path to an executable file) and returns a Runner.
// An empty homedir uses gpg's default ($GNUPGHOME or ~/.gnupg).
func NewRunner(bin, homedir string) (*Runner, error) {
	if !filepath.IsAbs(bin) {
		return nil, fmt.Errorf("gpg path must be absolute: %q", bin)
	}
	info, err := os.Stat(bin)
	if err != nil {
		return nil, fmt.Errorf("gpg binary: %w", err)
	}
	isExecutableFile := info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
	if !isExecutableFile {
		return nil, fmt.Errorf("gpg binary is not an executable file: %s", bin)
	}
	return &Runner{bin: bin, homedir: homedir}, nil
}

// ResolveBinary returns the configured path if set, otherwise gpg from PATH.
// exec.LookPath refuses PATH entries relative to the working directory.
func ResolveBinary(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	found, err := exec.LookPath("gpg")
	if err != nil {
		return "", fmt.Errorf("gpg not found in PATH: %w", err)
	}
	return filepath.Abs(found)
}

// Bin returns the absolute gpg path.
func (r *Runner) Bin() string { return r.bin }

// Argv returns the exact argument vector Run will execute.
func (r *Runner) Argv(c Command) []string {
	argv := []string{r.bin}
	if len(c.answers) > 0 {
		// Interactive commands cannot use --batch (gpg refuses e.g. --gen-revoke);
		// --no-tty keeps gpg's informational output off the terminal, since every
		// prompt is answered via the command fd.
		argv = append(argv, "--no-tty", "--status-fd", statusFD, "--command-fd", commandFDStr)
	} else {
		argv = append(argv, "--batch", "--status-fd", statusFD)
	}
	if r.homedir != "" {
		argv = append(argv, "--homedir", r.homedir)
	}
	argv = append(argv, c.options...)
	if len(c.operands) > 0 {
		argv = append(argv, "--")
		argv = append(argv, c.operands...)
	}
	return argv
}

// Preview returns the shell-quoted command line shown to the user before running.
func (r *Runner) Preview(c Command) string {
	return QuoteArgv(r.Argv(c))
}

// Run executes c. A non-zero gpg exit is reported in Result, not as an error;
// errors mean gpg could not be run or its output could not be read.
func (r *Runner) Run(ctx context.Context, c Command) (Result, error) {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun() // also aborts gpg when the answer feeder meets an unexpected prompt

	argv := r.Argv(c)
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...) //nolint:gosec // G204: argv built from typed Commands, no shell
	cmd.Env = environWithGPGTTY()
	cmd.Stdin = c.stdin
	cmd.WaitDelay = pipeWaitDelay

	stdout := &cappedBuffer{limit: maxCapturedStdoutBytes}
	if c.stdout != nil {
		cmd.Stdout = c.stdout
	} else {
		cmd.Stdout = stdout
	}
	stderr := &cappedBuffer{limit: maxStderrBytes}
	cmd.Stderr = stderr

	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return Result{}, fmt.Errorf("status pipe: %w", err)
	}
	defer statusRead.Close()
	cmd.ExtraFiles = []*os.File{statusWrite}

	// Commands with scripted answers: gpg reads them from fd 4 (the pipe's read
	// end); cryptosis writes them to the write end as prompts arrive.
	var feeder *answerFeeder
	var commandRead, commandWrite *os.File
	if len(c.answers) > 0 {
		commandRead, commandWrite, err = os.Pipe()
		if err != nil {
			_ = statusWrite.Close()
			return Result{}, fmt.Errorf("command pipe: %w", err)
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, commandRead)
		feeder = newAnswerFeeder(c.answers)
	}

	// Own process group: the terminal's Ctrl-C goes to cryptosis, which forwards it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	restoreTerminal := saveTerminalState()
	defer restoreTerminal()
	interrupts := newInterruptForwarder()
	defer interrupts.stop()

	startErr := cmd.Start()
	_ = statusWrite.Close() // child holds its own copy; ours must close for EOF
	if commandRead != nil {
		_ = commandRead.Close() // child's copy only, so answer writes fail with EPIPE once gpg exits
	}
	if startErr != nil {
		if commandWrite != nil {
			_ = commandWrite.Close()
		}
		return Result{}, fmt.Errorf("start gpg: %w", startErr)
	}

	observe := func(line StatusLine) { interrupts.observe(line) }
	if feeder != nil {
		commandWrite := commandWrite
		feeder.attach(func(answer string) error {
			_, err := commandWrite.WriteString(answer)
			return err
		}, cancelRun)
		observe = func(line StatusLine) {
			interrupts.observe(line)
			feeder.observe(line)
		}
		defer func() {
			feeder.stop()
			_ = commandWrite.Close()
		}()
	}

	interrupts.forwardTo(cmd.Process)
	statusCh := readStatus(statusRead, observe)
	waitErr := cmd.Wait()
	if feeder != nil {
		feeder.stop()
	}
	statuses, statusErr := awaitStatus(statusRead, statusCh)

	result := Result{
		ExitCode: cmd.ProcessState.ExitCode(),
		Status:   statuses,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}
	if feeder != nil && feeder.unexpectedPrompt() != "" {
		return result, fmt.Errorf("gpg asked for an unexpected prompt: %s", feeder.unexpectedPrompt())
	}
	return result, runError(runCtx, waitErr, statusErr)
}

func runError(ctx context.Context, waitErr, statusErr error) error {
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("gpg cancelled: %w", ctx.Err())
	case waitErr != nil && !errors.As(waitErr, &exitErr):
		return fmt.Errorf("gpg i/o: %w", waitErr)
	case statusErr != nil:
		return fmt.Errorf("gpg status: %w", statusErr)
	}
	return nil
}

type statusOutcome struct {
	lines Statuses
	err   error
}

// readStatus collects status lines, passing each to observe as it arrives.
func readStatus(r io.Reader, observe func(StatusLine)) <-chan statusOutcome {
	ch := make(chan statusOutcome, 1)
	go func() {
		var outcome statusOutcome
		scanner := bufio.NewScanner(io.LimitReader(r, maxStatusBytes))
		scanner.Buffer(make([]byte, 0, 4096), maxStatusLineBytes)
		for scanner.Scan() {
			if line, ok := ParseStatusLine(scanner.Text()); ok {
				observe(line)
				outcome.lines = append(outcome.lines, line)
			}
		}
		outcome.err = scanner.Err()
		ch <- outcome
	}()
	return ch
}

// awaitStatus waits for the status reader, bounded in case a gpg helper process
// inherited the status pipe and keeps it open.
func awaitStatus(statusRead *os.File, ch <-chan statusOutcome) (Statuses, error) {
	if err := statusRead.SetReadDeadline(time.Now().Add(statusDrainTimeout)); err != nil {
		return nil, err
	}
	outcome := <-ch
	if errors.Is(outcome.err, os.ErrDeadlineExceeded) {
		return outcome.lines, errors.New("status stream did not close after gpg exited")
	}
	return outcome.lines, outcome.err
}

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		return 0, ErrOutputTooLarge
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }
