package dirlist

import (
	"os"
	"syscall"
	"time"
)

// created returns the file's birth time from fstat.
func created(_ *os.File, info os.FileInfo) time.Time {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(stat.Birthtimespec.Unix())
}
