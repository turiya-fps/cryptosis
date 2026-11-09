package gpg

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestParsePinentryPID(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		want   int
		wantOK bool
	}{
		{"plain", []string{"95347", "mac", "1.3.1.1", "/dev/ttys004"}, 95347, true},
		{"with extra", []string{"495:1", "curses", "1.1.1"}, 495, true},
		{"empty", nil, 0, false},
		{"not a number", []string{"abc", "tty"}, 0, false},
		{"init pid refused", []string{"1", "tty"}, 0, false},
		{"negative refused", []string{"-5", "tty"}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parsePinentryPID(tc.args)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("parsePinentryPID(%q) = %d, %v; want %d, %v", tc.args, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestShouldCancelPinentry(t *testing.T) {
	tests := []struct {
		name                   string
		pinentryPID, cancelled int
		want                   bool
	}{
		{"no pinentry yet", 0, 0, false},
		{"first ctrl-c cancels pinentry", 495, 0, true},
		{"second ctrl-c goes to gpg", 495, 495, false},
		{"new pinentry after cancel", 496, 495, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldCancelPinentry(tc.pinentryPID, tc.cancelled); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestObserveRecordsLatestPinentry(t *testing.T) {
	forwarder := newInterruptForwarder()
	defer forwarder.stop()

	forwarder.observe(StatusLine{Keyword: "PINENTRY_LAUNCHED", Args: []string{"495", "curses"}})
	forwarder.observe(StatusLine{Keyword: "BEGIN_SIGNING", Args: []string{"H8"}})
	forwarder.observe(StatusLine{Keyword: "PINENTRY_LAUNCHED", Args: []string{"496", "curses"}})

	if got := forwarder.pinentryPID.Load(); got != 496 {
		t.Errorf("pinentry pid = %d, want 496", got)
	}
}

// Ctrl-C with no pinentry open must interrupt gpg and leave cryptosis running.
func TestRunForwardsInterruptToGPG(t *testing.T) {
	runner, _ := newTestRunner(t)
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinRead.Close()
	defer stdinWrite.Close() // held open so gpg blocks reading stdin
	blockedOnStdin := Command{label: "test blocked", options: []string{"--enarmor"}}.WithStdin(stdinRead)
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()

	result, err := runner.Run(context.Background(), blockedOnStdin)

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode == 0 {
		t.Errorf("gpg exit = 0, want interrupted")
	}
}
