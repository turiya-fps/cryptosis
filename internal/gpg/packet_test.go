package gpg

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/gpgtest"
)

func TestDetectPacket(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want PacketKind
	}{
		{"empty", nil, PacketNone},
		{"text", []byte("hello"), PacketNone},
		{"old PKESK v3, 1-octet length", []byte{0x84, 0x5e, 0x03}, PacketEncrypted},
		{"old PKESK v3, 2-octet length", []byte{0x85, 0x01, 0x0c, 0x03}, PacketEncrypted},
		{"old PKESK v3, 4-octet length", []byte{0x86, 0, 0, 0x01, 0x0c, 0x03}, PacketEncrypted},
		{"old SKESK v4", []byte{0x8c, 0x0d, 0x04}, PacketEncrypted},
		{"new PKESK v6, 1-octet length", []byte{0xc1, 0x5e, 0x06}, PacketEncrypted},
		{"new PKESK v3, 2-octet length", []byte{0xc1, 0xc0, 0x10, 0x03}, PacketEncrypted},
		{"new PKESK v3, 5-octet length", []byte{0xc1, 0xff, 0, 0, 0x01, 0x0c, 0x03}, PacketEncrypted},
		{"new SKESK v5 (LibrePGP)", []byte{0xc3, 0x3d, 0x05}, PacketEncrypted},
		{"PKESK bad version", []byte{0x84, 0x5e, 0x07}, PacketNone},
		{"PKESK truncated before version", []byte{0x84, 0x5e}, PacketNone},
		{"new header truncated", []byte{0xc1}, PacketNone},
		{"old signature", []byte{0x89, 0x01, 0x33, 0x04}, PacketOther},
		{"new public key", []byte{0xc6, 0x33, 0x04}, PacketOther},
		{"old compressed, indeterminate length", []byte{0xa3, 0x01}, PacketOther},
		{"new literal, partial length", []byte{0xcb, 0xe1, 0x62}, PacketOther},
		{"reserved tag 0", []byte{0x80, 0x01, 0x00}, PacketNone},
		{"unlisted tag (user ID)", []byte{0xcd, 0x05, 'a'}, PacketNone},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := DetectPacket(testCase.data); got != testCase.want {
				t.Errorf("DetectPacket(% x) = %v, want %v", testCase.data, got, testCase.want)
			}
		})
	}
}

// TestDetectPacketRealGPG checks the heuristic against what the installed gpg emits.
func TestDetectPacketRealGPG(t *testing.T) {
	bin := gpgtest.Binary(t)
	home := gpgtest.NewHome(t, bin)
	fpr := gpgtest.GenerateKey(t, bin, home, "Own <own@example.org>")
	gpgOut := func(stdin []byte, args ...string) []byte {
		t.Helper()
		base := []string{"--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""}
		cmd := exec.Command(bin, append(base, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg %v: %v", args, err)
		}
		return out
	}
	cases := map[string]struct {
		data []byte
		want PacketKind
	}{
		"public-key encrypted": {gpgOut([]byte("x"), "--encrypt", "--recipient", fpr), PacketEncrypted},
		"symmetric encrypted":  {gpgOut([]byte("x"), "--symmetric", "--passphrase", "pw"), PacketEncrypted},
		"detached signature":   {gpgOut([]byte("x"), "--detach-sign"), PacketOther},
		"signed message":       {gpgOut([]byte("x"), "--sign"), PacketOther},
		"exported public key":  {gpgOut(nil, "--export", fpr), PacketOther},
		"armored message":      {gpgOut([]byte("x"), "--encrypt", "--armor", "--recipient", fpr), PacketNone},
	}
	for name, testCase := range cases {
		if got := DetectPacket(testCase.data); got != testCase.want {
			t.Errorf("%s: DetectPacket = %v, want %v (first bytes % x)", name, got, testCase.want, testCase.data[:min(8, len(testCase.data))])
		}
	}
}

func FuzzDetectPacket(f *testing.F) {
	for _, seed := range [][]byte{nil, {0x84, 0x5e, 0x03}, {0xc1, 0xff, 0, 0, 0, 1, 6}, {0xcb, 0xe1}, []byte("text")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		kind := DetectPacket(data)
		if kind != PacketNone && (len(data) == 0 || data[0]&0x80 == 0) {
			t.Fatalf("non-packet data classified as %v: % x", kind, data)
		}
	})
}
