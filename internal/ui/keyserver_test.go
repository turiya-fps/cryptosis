package ui

import (
	"strings"
	"testing"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/keyserver"
)

func TestCheckImportedKeys(t *testing.T) {
	right := strings.Repeat("A", 24) + strings.Repeat("5", 16)
	other := strings.Repeat("B", 40)

	// Fingerprint or key-ID queries must match the returned key.
	if err := checkImportedKeys([]gpg.Key{validKey(right, "q")}, importCheck{wantFprSuffix: strings.Repeat("5", 16)}); err != nil {
		t.Fatalf("full fpr: %v", err)
	}
	if err := checkImportedKeys([]gpg.Key{validKey(right, "q")}, importCheck{wantFprSuffix: right}); err != nil {
		t.Fatalf("key id: %v", err)
	}
	if err := checkImportedKeys([]gpg.Key{validKey(other, "q")}, importCheck{wantFprSuffix: strings.Repeat("5", 16)}); err == nil {
		t.Fatal("wrong key accepted")
	}

	// Email queries must find the address in a user ID.
	emailKey := validKey(right, "q")
	emailKey.UIDs = []gpg.UID{{UserID: "Alice <alice@example.org>"}}
	if err := checkImportedKeys([]gpg.Key{emailKey}, importCheck{wantEmail: "alice@example.org"}); err != nil {
		t.Fatalf("email match: %v", err)
	}
	lookalike := validKey(right, "q")
	lookalike.UIDs = []gpg.UID{{UserID: "Mallory <evil-alice@example.org>"}}
	if err := checkImportedKeys([]gpg.Key{lookalike}, importCheck{wantEmail: "alice@example.org"}); err == nil {
		t.Fatal("lookalike address accepted")
	}
	uidLess := validKey(right, "q")
	uidLess.UIDs = nil
	if err := checkImportedKeys([]gpg.Key{uidLess}, importCheck{wantEmail: "alice@example.org"}); err == nil {
		t.Fatal("UID-less key accepted for an email query")
	}
}

func TestUIDEmailAddresses(t *testing.T) {
	uids := []gpg.UID{
		{UserID: "Alice <alice@example.org>"},
		{UserID: "plain@address.example"},
		{UserID: "Weird <<x@y.example>"},
		{UserID: "no address here"},
	}
	got := strings.Join(uidEmailAddresses(uids), ",")
	if want := "alice@example.org,plain@address.example,x@y.example"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSearchResultLabel(t *testing.T) {
	label := searchResultLabel(keyserver.SearchResult{
		Fingerprint: strings.Repeat("A", 40),
		Created:     1672531200,
		UIDs:        []string{"Alice <alice@example.org>", "Second"},
	})
	for _, want := range []string{
		"AAAA AAAA", "2023-01-01", "Alice <alice@example.org>", "(+1 more)",
	} {
		if !strings.Contains(label, want) {
			t.Fatalf("label %q missing %q", label, want)
		}
	}
	if strings.Contains(searchResultLabel(keyserver.SearchResult{Fingerprint: strings.Repeat("A", 16), Revoked: true}), "[revoked]") == false {
		t.Fatal("revoked flag missing")
	}
}

func TestValidateFprOrKeyIDOrEmpty(t *testing.T) {
	for _, ok := range []string{"", "  ", "ABCDEF0123456789", strings.Repeat("A", 40), strings.Repeat("a", 64)} {
		if err := validateFprOrKeyIDOrEmpty(ok); err != nil {
			t.Fatalf("validateFprOrKeyIDOrEmpty(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"XYZ", "12345", "0x1234567890ABCDEF", "GGGGGGGGGGGGGGGG"} {
		if err := validateFprOrKeyIDOrEmpty(bad); err == nil {
			t.Fatalf("validateFprOrKeyIDOrEmpty(%q) accepted", bad)
		}
	}
}

func TestValidateEmailOrEmpty(t *testing.T) {
	for _, ok := range []string{"", "a@e.org", "First.Last@Example.COM"} {
		if err := validateEmailOrEmpty(ok); err != nil {
			t.Fatalf("validateEmailOrEmpty(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"nope", "a@b", "a b@e.org"} {
		if err := validateEmailOrEmpty(bad); err == nil {
			t.Fatalf("validateEmailOrEmpty(%q) accepted", bad)
		}
	}
}
