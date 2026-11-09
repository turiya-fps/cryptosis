package gpg

import (
	"errors"
	"os"
	"testing"
	"time"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseKeysPublicListing(t *testing.T) {
	keys, err := ParseKeys(readFixture(t, "public-keys.colons"))
	if err != nil {
		t.Fatalf("ParseKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}

	modern := keys[0]
	if modern.Secret {
		t.Error("public key marked secret")
	}
	if modern.Fingerprint != "BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72" {
		t.Errorf("fingerprint = %q", modern.Fingerprint)
	}
	if modern.AlgoName() != "ed25519" || modern.Capabilities != "scESC" || modern.OwnerTrust != "u" {
		t.Errorf("algo/caps/trust = %q/%q/%q", modern.AlgoName(), modern.Capabilities, modern.OwnerTrust)
	}
	if want := time.Unix(1857321022, 0).UTC(); !modern.Expires.Equal(want) {
		t.Errorf("expires = %v, want %v", modern.Expires, want)
	}
	if len(modern.UIDs) != 1 || modern.UIDs[0].UserID != "Test: User <t@example.org>" {
		t.Errorf("uids = %+v", modern.UIDs)
	}
	if len(modern.Subkeys) != 1 || modern.Subkeys[0].Fingerprint != "D737A7024C7BE62566570F7FAE15556F3D6C30EE" {
		t.Errorf("subkeys = %+v", modern.Subkeys)
	}
	if !modern.Subkeys[0].Expires.IsZero() {
		t.Errorf("subkey without expiry parsed as %v", modern.Subkeys[0].Expires)
	}
}

func TestParseKeysUnescapesUserIDsWithoutSanitizing(t *testing.T) {
	keys, err := ParseKeys(readFixture(t, "public-keys.colons"))
	if err != nil {
		t.Fatalf("ParseKeys: %v", err)
	}

	legacy := keys[1]

	if legacy.UIDs[0].UserID != "Evil\x1b[2J\\name <e@example.org>" {
		t.Errorf("uid = %q", legacy.UIDs[0].UserID)
	}
	if len(legacy.UIDs) != 2 {
		t.Errorf("got %d uids, want 2", len(legacy.UIDs))
	}
}

func TestParseKeysAcceptsV5FingerprintsAndUnknownAlgos(t *testing.T) {
	keys, err := ParseKeys(readFixture(t, "public-keys.colons"))
	if err != nil {
		t.Fatalf("ParseKeys: %v", err)
	}

	if len(keys[1].Fingerprint) != 64 || keys[1].AlgoName() != "RSA 4096" {
		t.Errorf("v5 key: fpr %q algo %q", keys[1].Fingerprint, keys[1].AlgoName())
	}
	if keys[2].AlgoName() != "algo 99" {
		t.Errorf("unknown algo name = %q", keys[2].AlgoName())
	}
	if want := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC); !keys[2].Created.Equal(want) {
		t.Errorf("ISO created = %v, want %v", keys[2].Created, want)
	}
}

func TestParseKeysSecretListing(t *testing.T) {
	keys, err := ParseKeys(readFixture(t, "secret-keys.colons"))
	if err != nil {
		t.Fatalf("ParseKeys: %v", err)
	}

	if len(keys) != 1 || !keys[0].Secret {
		t.Fatalf("keys = %+v", keys)
	}
	if keys[0].Subkeys[0].Fingerprint != "D737A7024C7BE62566570F7FAE15556F3D6C30EE" {
		t.Errorf("keygrip grp record leaked into fingerprint: %q", keys[0].Subkeys[0].Fingerprint)
	}
}

func TestParseKeysRejectsMalformedListings(t *testing.T) {
	tests := map[string]string{
		"subkey first":       "sub:u:255:18:AE15556F3D6C30EE:1794249022::::::e:::::cv25519::\n",
		"uid first":          "uid:u::::1::X::name::\n",
		"invalid fpr":        "pub:u:255:22:438F68FF5D06DB72:1::::::sc:\nfpr:::::::::bb11b7dc:\n",
		"missing fpr":        "pub:u:255:22:438F68FF5D06DB72:1::::::sc:\n",
		"lower-case fpr":     "pub:u:255:22:438F68FF5D06DB72:1::::::sc:\nfpr:::::::::bb11b7dc4d321fccfb1212e7438f68ff5d06db72:\n",
		"missing subkey fpr": "pub:u:255:22:438F68FF5D06DB72:1::::::sc:\nfpr:::::::::BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72:\nsub:u:255:18:AE15556F3D6C30EE:1::::::e:\n",
	}
	for name, listing := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKeys([]byte(listing))
			if !errors.Is(err, ErrMalformedListing) {
				t.Errorf("err = %v, want ErrMalformedListing", err)
			}
		})
	}
}

func TestUnescapeColonField(t *testing.T) {
	tests := map[string]string{
		`plain`:      "plain",
		`a\x3ab`:     "a:b",
		`a\x5cx41`:   `a\x41`,
		`bad\xZZ`:    `bad\xZZ`,
		`trailing\x`: `trailing\x`,
		`short\x4`:   `short\x4`,
	}
	for in, want := range tests {
		if got := unescapeColonField(in); got != want {
			t.Errorf("unescapeColonField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsFingerprint(t *testing.T) {
	tests := map[string]bool{
		"BB11B7DC4D321FCCFB1212E7438F68FF5D06DB72":                         true,
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF": true,
		"bb11b7dc4d321fccfb1212e7438f68ff5d06db72":                         false,
		"438F68FF5D06DB72":                         false,
		"BB11B7DC4D321FCCFB1212E7438F68FF5D06DB7G": false,
		"--delete-secret-keys":                     false,
		"":                                         false,
	}
	for in, want := range tests {
		if got := IsFingerprint(in); got != want {
			t.Errorf("IsFingerprint(%q) = %v, want %v", in, got, want)
		}
	}
}

func FuzzParseKeys(f *testing.F) {
	f.Add(readFixtureForFuzz(f, "public-keys.colons"))
	f.Add(readFixtureForFuzz(f, "secret-keys.colons"))
	f.Add([]byte("pub:::\nfpr\nuid\nsub\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := ParseKeys(data)
		if err != nil {
			return
		}
		for _, key := range keys {
			if !IsFingerprint(key.Fingerprint) {
				t.Fatalf("accepted key with invalid fingerprint %q", key.Fingerprint)
			}
			_ = key.AlgoName()
		}
	})
}

func readFixtureForFuzz(f *testing.F, name string) []byte {
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		f.Fatal(err)
	}
	return data
}
