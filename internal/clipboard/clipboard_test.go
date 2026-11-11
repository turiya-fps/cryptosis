package clipboard

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClipboard records writes and simulates the stored content, optionally
// failing like a missing clipboard utility.
type fakeClipboard struct {
	mu       sync.Mutex
	content  string
	writes   []string
	writeErr error
	readErr  error
}

func (f *fakeClipboard) write(text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, text)
	f.content = text
	return nil
}

func (f *fakeClipboard) read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.content, nil
}

func (f *fakeClipboard) lastWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition not reached in time")
	}
}

func TestSetWithoutClearDoesNotSchedule(t *testing.T) {
	fake := &fakeClipboard{}
	manager := newManager(readWriter{write: fake.write, read: fake.read})

	if err := manager.Set("plain", 0); err != nil {
		t.Fatal(err)
	}

	if writes := fake.lastWrites(); len(writes) != 1 || writes[0] != "plain" {
		t.Errorf("writes = %v", writes)
	}
	if err := manager.Set("x", 0); err != nil {
		t.Fatal(err)
	}
	if got, err := fake.read(); err != nil || got != "x" {
		t.Errorf("content = %q, %v", got, err)
	}
}

func TestAutoClearRemovesOnlyUnchangedContent(t *testing.T) {
	fake := &fakeClipboard{}
	manager := newManager(readWriter{write: fake.write, read: fake.read})

	if err := manager.Set("secret", 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := fake.write("user pasted their own thing"); err != nil { // user replaced it
		t.Fatal(err)
	}

	time.Sleep(80 * time.Millisecond) // give the clear timer ample time to fire

	for _, write := range fake.lastWrites() {
		if write == "" {
			t.Fatalf("clipboard cleared although content changed: %v", fake.lastWrites())
		}
	}
}

func TestAutoClearClearsUnchangedContent(t *testing.T) {
	fake := &fakeClipboard{}
	manager := newManager(readWriter{write: fake.write, read: fake.read})

	if err := manager.Set("secret", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	cleared := func() bool {
		writes := fake.lastWrites()
		return len(writes) > 1 && writes[len(writes)-1] == ""
	}
	waitFor(t, time.Second, cleared)
	if content, err := fake.read(); err != nil || content != "" {
		t.Errorf("content = %q, %v, want cleared", content, err)
	}
}

func TestFlushClearsPendingImmediately(t *testing.T) {
	fake := &fakeClipboard{}
	manager := newManager(readWriter{write: fake.write, read: fake.read})

	if err := manager.Set("secret", time.Hour); err != nil {
		t.Fatal(err)
	}

	manager.Flush()

	if writes := fake.lastWrites(); len(writes) < 2 || writes[len(writes)-1] != "" {
		t.Fatalf("writes = %v, want an immediate clear", writes)
	}
	if err := manager.Set("later", 0); err != nil {
		t.Fatal(err)
	}
	if content, err := fake.read(); err != nil || content != "later" {
		t.Fatalf("content = %q, %v; clipboard unusable after flush", content, err)
	}
}

func TestSetMapsMissingUtilityError(t *testing.T) {
	fake := &fakeClipboard{writeErr: errors.New("No clipboard utilities available, please install xclip or xsel")}
	manager := newManager(readWriter{write: fake.write, read: fake.read})

	err := manager.Set("x", 0)

	if !IsNoUtility(err) {
		t.Fatalf("err = %v, want no-utility error", err)
	}
	if IsNoUtility(errors.New("unrelated")) {
		t.Error("unrelated error classified as no-utility")
	}
}
