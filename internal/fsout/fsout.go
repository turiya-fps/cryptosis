// Package fsout writes output files atomically: data goes to a private temp
// file beside the destination, which is renamed into place only on success.
// A failed or cancelled operation never leaves a partial or plaintext file at
// the destination, and gpg's own 0644 output mode is never used.
package fsout

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrExists is returned by Commit when the destination exists and overwrite was not allowed.
var ErrExists = errors.New("destination file already exists")

// File is a pending output. Exactly one of Commit or Abort must be called.
type File struct {
	temp     *os.File
	dest     string
	finished bool
}

// Create opens a new 0600 temp file in dest's directory. dest must be absolute.
func Create(dest string) (*File, error) {
	if !filepath.IsAbs(dest) {
		return nil, fmt.Errorf("output path must be absolute: %q", dest)
	}
	// os.CreateTemp uses O_EXCL and mode 0600.
	temp, err := os.CreateTemp(filepath.Dir(dest), filepath.Base(dest)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp output: %w", err)
	}
	return &File{temp: temp, dest: dest}, nil
}

// Exists reports whether dest exists (without following a final symlink), so
// the UI can ask before an operation rather than after.
func Exists(dest string) (bool, error) {
	_, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Writer returns the temp file for gpg's stdout; an *os.File is handed to gpg directly.
func (f *File) Writer() *os.File { return f.temp }

// Dest returns the destination path.
func (f *File) Dest() string { return f.dest }

// Commit syncs the temp file and moves it to the destination. Without
// overwrite, an existing destination is never replaced, even if it appeared
// after the user confirmed. On error the temp file is removed.
func (f *File) Commit(overwrite bool) error {
	if f.finished {
		return errors.New("output already finished")
	}
	f.finished = true
	tempPath := f.temp.Name()
	defer os.Remove(tempPath) // no-op after a successful rename

	if err := f.temp.Sync(); err != nil {
		_ = f.temp.Close() // sync error is the one worth reporting
		return fmt.Errorf("sync output: %w", err)
	}
	if err := f.temp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if overwrite {
		return os.Rename(tempPath, f.dest)
	}
	return linkWithoutOverwrite(tempPath, f.dest)
}

// Abort discards the output. Safe to call after Commit (it then does nothing).
func (f *File) Abort() error {
	if f.finished {
		return nil
	}
	f.finished = true
	closeErr := f.temp.Close()
	removeErr := os.Remove(f.temp.Name())
	return errors.Join(closeErr, removeErr)
}

// linkWithoutOverwrite uses link(2), which fails atomically if dest exists.
func linkWithoutOverwrite(tempPath, dest string) error {
	err := os.Link(tempPath, dest)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s", ErrExists, dest)
	}
	if err != nil {
		return fmt.Errorf("move output into place: %w", err)
	}
	return nil
}
