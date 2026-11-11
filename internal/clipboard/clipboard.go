// Package clipboard copies text to the system clipboard and can clear it
// again after a delay — but only when its content was not replaced in the
// meantime, so a later copy by the user or another program is never wiped.
package clipboard

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

// writeText and readText are swappable for tests.
type readWriter struct {
	write func(string) error
	read  func() (string, error)
}

// Manager serializes clipboard use and tracks pending automatic clears.
type Manager struct {
	mu      sync.Mutex
	io      readWriter
	pending []*pendingClear
}

type pendingClear struct {
	content string
	timer   *time.Timer
}

// NewManager returns a Manager using the system clipboard.
func NewManager() *Manager {
	return newManager(readWriter{write: clipboard.WriteAll, read: clipboard.ReadAll})
}

func newManager(io readWriter) *Manager {
	return &Manager{io: io}
}

// Set copies text, and when clearAfter is positive schedules a clear of that
// exact content. A clear happens only if the clipboard still holds it.
func (m *Manager) Set(text string, clearAfter time.Duration) error {
	if err := m.io.write(text); err != nil {
		return opError("copy to clipboard", err)
	}
	if clearAfter <= 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := &pendingClear{content: text}
	entry.timer = time.AfterFunc(clearAfter, func() { m.clearIfUnchanged(entry) })
	m.pending = append(m.pending, entry)
	return nil
}

// Read returns the current clipboard content.
func (m *Manager) Read() (string, error) {
	text, err := m.io.read()
	if err != nil {
		return "", opError("read clipboard", err)
	}
	return text, nil
}

// Flush runs every pending clear immediately (stopping their timers); called
// on exit so text copied near the end of a session is still cleared.
func (m *Manager) Flush() {
	m.mu.Lock()
	entries := m.pending
	m.pending = nil
	m.mu.Unlock()
	for _, entry := range entries {
		entry.timer.Stop()
	}
	for _, entry := range entries {
		m.clearIfUnchanged(entry)
	}
}

// clearIfUnchanged replaces the clipboard with an empty string only when it
// still contains exactly the content cryptosis copied.
func (m *Manager) clearIfUnchanged(entry *pendingClear) {
	m.mu.Lock()
	for i, p := range m.pending {
		if p == entry {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	current, err := m.io.read()
	if err != nil || current != entry.content {
		return
	}
	// Best effort: a concurrent clipboard change may win the race.
	_ = m.io.write("")
}

// opError turns clipboard utility failures into an actionable message.
func opError(op string, err error) error {
	if clipboard.Unsupported || strings.Contains(err.Error(), "No clipboard utilities") {
		return &NoUtilityError{op: op}
	}
	return fmt.Errorf("%s: %w", op, err)
}

// NoUtilityError reports that no system clipboard utility is available.
type NoUtilityError struct {
	op string
}

func (e *NoUtilityError) Error() string {
	return e.op + ": no clipboard utility found; install wl-copy, xclip or xsel (Linux) or use another destination"
}

// IsNoUtility reports whether err means no clipboard utility is installed.
func IsNoUtility(err error) bool {
	var noUtility *NoUtilityError
	return errors.As(err, &noUtility)
}
