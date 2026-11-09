package gpg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanConfigFindsRiskyOptions(t *testing.T) {
	conf := `# comment
keyserver hkps://keys.openpgp.org
trust-model always
--encrypt-to 0xDEADBEEF
pinentry-mode loopback
keyserver-options include-revoked,auto-key-retrieve
[ignore]
`
	warnings, err := ScanConfig(strings.NewReader(conf), "gpg.conf")
	if err != nil {
		t.Fatal(err)
	}

	got := optionsOf(warnings)
	want := []string{"trust-model always", "encrypt-to 0xDEADBEEF", "pinentry-mode loopback", "keyserver-options include-revoked,auto-key-retrieve"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("warnings = %q, want %q", got, want)
	}
}

func TestScanConfigIgnoresSafeValues(t *testing.T) {
	conf := "trust-model pgp\npinentry-mode ask\nkeyserver-options include-revoked\n"

	warnings, err := ScanConfig(strings.NewReader(conf), "gpg.conf")

	if err != nil || len(warnings) != 0 {
		t.Errorf("warnings = %+v, err = %v", warnings, err)
	}
}

func TestScanConfigHonoursLaterOverrides(t *testing.T) {
	conf := "auto-key-retrieve\nno-auto-key-retrieve\ntrust-model always\ntrust-model pgp\nencrypt-to A\nencrypt-to B\n"

	warnings, err := ScanConfig(strings.NewReader(conf), "gpg.conf")
	if err != nil {
		t.Fatal(err)
	}

	got := optionsOf(warnings)
	if len(got) != 1 || got[0] != "encrypt-to B" {
		t.Errorf("warnings = %q, want [encrypt-to B]", got)
	}
}

func TestUserConfigFilePrefersMostSpecificVersion(t *testing.T) {
	home := t.TempDir()
	version := Version{2, 4, 4}
	for _, name := range []string{"gpg.conf", "gpg.conf-2", "gpg.conf-2.4"} {
		if err := os.WriteFile(filepath.Join(home, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := userConfigFile(home, version)

	if want := filepath.Join(home, "gpg.conf-2.4"); got != want {
		t.Errorf("userConfigFile = %q, want %q", got, want)
	}
}

func TestParseGpgconfDirs(t *testing.T) {
	out := "sysconfdir:/etc/gnupg\nhomedir:/Users/a%3ab/.gnupg\nsocketdir:/run/user/1000/gnupg\n"

	dirs, err := parseGpgconfDirs([]byte(out))

	if err != nil || dirs["homedir"] != "/Users/a:b/.gnupg" || dirs["sysconfdir"] != "/etc/gnupg" {
		t.Errorf("dirs = %v, err = %v", dirs, err)
	}
}

func optionsOf(warnings []ConfigWarning) []string {
	options := make([]string, len(warnings))
	for i, warning := range warnings {
		options[i] = warning.Option
	}
	return options
}
