// Package dirlist lists a directory for the file browser: subdirectories and
// regular files with their detected content type and timestamps.
//
// Dotfiles and anything that is not a directory or regular file (symlinks,
// FIFOs, sockets, devices) are skipped. Files are opened without following
// symlinks and without blocking, and must still be regular once open, so an
// entry swapped after the listing cannot redirect or hang a read.
package dirlist

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

// detectBytes is how much of each file is read to classify it (matches the
// window gpg.DetectArmor searches).
const detectBytes = 8 << 10

// Kind is an entry's type, detected from content rather than the extension.
type Kind int

// Entry kinds.
const (
	Dir             Kind = iota
	ArmoredMessage       // -----BEGIN PGP MESSAGE-----
	BinaryEncrypted      // binary OpenPGP starting with a session key packet
	Signature            // armored detached or cleartext signature
	Key                  // armored public or private key block
	OpenPGPOther         // other binary OpenPGP (signature, key, signed data)
	Text
	Binary
	Unreadable
)

// Entry is one listed directory or file. Directories carry only Name and Kind.
type Entry struct {
	Name     string
	Kind     Kind
	Size     int64
	Modified time.Time
	Created  time.Time // zero when the OS or filesystem does not record it
}

// Listing is a directory's entries: directories by name, then files newest
// modified first.
type Listing struct {
	Entries   []Entry
	Truncated bool // more than the requested number of files existed
}

// List lists dir, keeping at most maxFiles files (the newest); directories
// are never capped.
func List(dir string, maxFiles int) (Listing, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return Listing{}, err
	}
	type candidate struct {
		name     string
		modified time.Time
	}
	var dirs []Entry
	var files []candidate
	for _, dirEntry := range dirEntries {
		name := dirEntry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		switch {
		case dirEntry.Type().IsDir():
			dirs = append(dirs, Entry{Name: name, Kind: Dir})
		case dirEntry.Type().IsRegular():
			info, err := dirEntry.Info()
			if err != nil { // removed since ReadDir
				continue
			}
			files = append(files, candidate{name, info.ModTime()})
		}
	}
	// ReadDir returns names sorted, so dirs are already in order.
	slices.SortStableFunc(files, func(a, b candidate) int { return b.modified.Compare(a.modified) })
	listing := Listing{Entries: dirs, Truncated: len(files) > maxFiles}
	files = files[:min(len(files), maxFiles)]
	for _, file := range files {
		entry, keep := inspect(filepath.Join(dir, file.name))
		if !keep {
			continue
		}
		if entry.Modified.IsZero() { // could not open: keep the listing's time
			entry.Modified = file.modified
		}
		listing.Entries = append(listing.Entries, entry)
	}
	return listing, nil
}

// inspect opens path and classifies it. keep is false when the entry is no
// longer a regular file (replaced or removed since the listing).
func inspect(path string) (entry Entry, keep bool) {
	entry = Entry{Name: filepath.Base(path), Kind: Unreadable}
	file, info, err := openRegular(path)
	if err != nil {
		vanished := errors.Is(err, errNotRegular) || errors.Is(err, syscall.ELOOP) || errors.Is(err, os.ErrNotExist)
		return entry, !vanished
	}
	defer file.Close()
	entry.Size = info.Size()
	entry.Modified = info.ModTime()
	entry.Created = created(file, info)

	head := make([]byte, detectBytes)
	n, err := io.ReadFull(file, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return entry, true
	}
	entry.Kind = classify(head[:n], n == detectBytes)
	return entry, true
}

func classify(head []byte, truncated bool) Kind {
	switch gpg.DetectArmor(head) {
	case gpg.ArmorMessage:
		return ArmoredMessage
	case gpg.ArmorSignature, gpg.ArmorSignedMessage:
		return Signature
	case gpg.ArmorPublicKey, gpg.ArmorPrivateKey:
		return Key
	case gpg.ArmorNone:
	}
	switch gpg.DetectPacket(head) {
	case gpg.PacketEncrypted:
		return BinaryEncrypted
	case gpg.PacketOther:
		return OpenPGPOther
	case gpg.PacketNone:
	}
	if truncated {
		head = trimPartialRune(head)
	}
	if IsText(head) {
		return Text
	}
	return Binary
}

// trimPartialRune drops an incomplete UTF-8 sequence cut off by the read window.
func trimPartialRune(b []byte) []byte {
	for i := 1; i < utf8.UTFMax && i <= len(b); i++ {
		if utf8.RuneStart(b[len(b)-i]) {
			if !utf8.FullRune(b[len(b)-i:]) {
				return b[:len(b)-i]
			}
			break
		}
	}
	return b
}

var errNotRegular = errors.New("not a regular file")

// openRegular opens path read-only without following a symlink or blocking
// on a FIFO, and requires the opened file to be regular.
func openRegular(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: file inside the user's configured directory, read only
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.Join(errNotRegular, file.Close())
	}
	return file, info, nil
}

// Open opens a file for reading, refusing symlinks and non-regular files, and
// returns it with its fstat info, so size checks and reads see the same file.
func Open(path string) (*os.File, os.FileInfo, error) {
	file, info, err := openRegular(path)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			err = errNotRegular
		}
		return nil, nil, fmt.Errorf("%s: %w", sanitize.Line(path), err)
	}
	return file, info, nil
}

// IsText reports whether b is valid UTF-8 without NUL bytes.
func IsText(b []byte) bool {
	return utf8.Valid(b) && !bytes.Contains(b, []byte{0})
}
