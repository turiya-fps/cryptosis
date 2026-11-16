package dirlist

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// created returns the file's birth time via statx, or zero when the kernel
// (< 4.11) or filesystem (e.g. tmpfs, some network filesystems) lacks it.
func created(file *os.File, _ os.FileInfo) time.Time {
	conn, err := file.SyscallConn()
	if err != nil {
		return time.Time{}
	}
	var stat unix.Statx_t
	var statErr error
	err = conn.Control(func(fd uintptr) {
		statErr = unix.Statx(int(fd), "", unix.AT_EMPTY_PATH, unix.STATX_BTIME, &stat) //nolint:gosec // G115: file descriptors fit in int
	})
	if err != nil || statErr != nil || stat.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}
	}
	return time.Unix(stat.Btime.Sec, int64(stat.Btime.Nsec))
}
