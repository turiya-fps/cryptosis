package gpg

import (
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/term"
)

// interruptForwarder turns Ctrl-C into a cancel of the open pinentry.
//
// gpg runs in its own process group, so the terminal's SIGINT reaches only
// cryptosis. Killing gpg directly would orphan a terminal pinentry on gpg-agent
// < 2.3 (no watch_sock in agent/call-pinentry.c), which then keeps reading the
// tty. Cancelling the pinentry instead makes gpg fail cleanly ("Operation
// cancelled") on every version. A second Ctrl-C, or one with no pinentry open,
// interrupts gpg itself.
type interruptForwarder struct {
	pinentryPID atomic.Int64
	signals     chan os.Signal
	done        chan struct{}
}

func newInterruptForwarder() *interruptForwarder {
	f := &interruptForwarder{signals: make(chan os.Signal, 1), done: make(chan struct{})}
	signal.Notify(f.signals, os.Interrupt)
	return f
}

// observe records the pid of each pinentry gpg reports launching.
func (f *interruptForwarder) observe(line StatusLine) {
	if line.Keyword != "PINENTRY_LAUNCHED" {
		return
	}
	if pid, ok := parsePinentryPID(line.Args); ok {
		f.pinentryPID.Store(int64(pid))
	}
}

// forwardTo starts delivering interrupts once gpg is running.
func (f *interruptForwarder) forwardTo(gpg *os.Process) {
	go func() {
		lastCancelled := 0
		for {
			select {
			case <-f.done:
				return
			case <-f.signals:
				lastCancelled = f.deliver(gpg, lastCancelled)
			}
		}
	}()
}

func (f *interruptForwarder) deliver(gpg *os.Process, lastCancelled int) int {
	pinentry := int(f.pinentryPID.Load())
	if shouldCancelPinentry(pinentry, lastCancelled) && syscall.Kill(pinentry, syscall.SIGINT) == nil {
		return pinentry
	}
	_ = gpg.Signal(os.Interrupt)
	return lastCancelled
}

func (f *interruptForwarder) stop() {
	signal.Stop(f.signals)
	close(f.done)
}

// shouldCancelPinentry: cancel each pinentry once; after that Ctrl-C goes to gpg.
func shouldCancelPinentry(pinentryPID, lastCancelled int) bool {
	return pinentryPID > 1 && pinentryPID != lastCancelled
}

// parsePinentryPID reads "PINENTRY_LAUNCHED <pid>[:<extra>] <flavor> ..." (gnupg doc/DETAILS).
func parsePinentryPID(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	pidField, _, _ := strings.Cut(args[0], ":")
	pid, err := strconv.Atoi(pidField)
	if err != nil || pid <= 1 {
		return 0, false
	}
	return pid, true
}

// saveTerminalState returns a function restoring stdin's terminal modes, which a
// pinentry sharing the tty may leave changed.
func saveTerminalState() (restore func()) {
	stdinFD := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFD) {
		return func() {}
	}
	saved, err := term.GetState(stdinFD)
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(stdinFD, saved) }
}
