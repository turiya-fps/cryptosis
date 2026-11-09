package gpg

import "testing"

func TestParseVersion(t *testing.T) {
	tests := map[string]Version{
		"gpg (GnuPG) 2.5.24\nlibgcrypt 1.12.4\n": {2, 5, 24},
		"gpg (GnuPG) 2.2.27\n":                   {2, 2, 27},
		"gpg (GnuPG/MacGPG2) 2.2.41\n":           {2, 2, 41},
		"gpg (GnuPG) 2.4.4-unknown\n":            {2, 4, 4},
		"gpg (GnuPG) 2.5.0-beta123\n":            {2, 5, 0},
	}
	for in, want := range tests {
		got, err := ParseVersion([]byte(in))
		if err != nil || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

func TestParseVersionRejectsUnknownOutput(t *testing.T) {
	for _, in := range []string{"", "gpg2 something\n", "gpg (GnuPG) 2.x.1\n", "gpg (GnuPG) 2.4\n", "sq 0.38.0\n"} {
		if _, err := ParseVersion([]byte(in)); err == nil {
			t.Errorf("ParseVersion(%q) accepted", in)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		v    Version
		want bool
	}{
		{Version{2, 2, 17}, true},
		{Version{2, 2, 16}, false},
		{Version{2, 2, 27}, true},
		{Version{2, 1, 99}, false},
		{Version{2, 4, 0}, true},
		{Version{3, 0, 0}, true},
		{Version{1, 4, 23}, false},
	}
	for _, tc := range tests {
		if got := tc.v.AtLeast(MinVersion); got != tc.want {
			t.Errorf("%v.AtLeast(%v) = %v, want %v", tc.v, MinVersion, got, tc.want)
		}
	}
}

func TestParseCapabilities(t *testing.T) {
	withOwnertrust := ParseCapabilities([]byte("--quick-set-expire\n--quick-set-ownertrust\n"))
	withoutOwnertrust := ParseCapabilities([]byte("--quick-set-expire\n--quick-set-ownertrust-x\n"))

	if !withOwnertrust.QuickSetOwnertrust {
		t.Error("--quick-set-ownertrust not detected")
	}
	if withoutOwnertrust.QuickSetOwnertrust {
		t.Error("--quick-set-ownertrust detected from a different option")
	}
}
