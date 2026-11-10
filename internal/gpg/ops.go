package gpg

import (
	"strconv"
	"strings"
)

// QuickGenerateKeyCommand creates a primary key plus default encryption
// subkey for uid. algo is a gpg key-algo name ("future-default", "default");
// expiry is gpg's relative form ("2y") or "never".
func QuickGenerateKeyCommand(uid, algo, expiry string) Command {
	return Command{
		label:    "Generate key",
		options:  []string{"--quick-generate-key"},
		operands: []string{uid, algo, "default", expiry},
	}
}

// ExportCommand exports the given keys (by fingerprint), armored or binary,
// secret keys when secret is set.
func ExportCommand(fprs []string, secret, armor bool) Command {
	option := "--export"
	label := "Export public key"
	if secret {
		option = "--export-secret-keys"
		label = "Export secret key"
	}
	options := []string{option}
	if armor {
		options = append(options, "--armor")
	}
	return Command{label: label, options: options, operands: fprs}
}

// DeleteCommand deletes a key. withSecret deletes the secret key and its
// public part together (gpg refuses to delete the public part of a key whose
// secret key is still present).
func DeleteCommand(fpr string, withSecret bool) Command {
	option := "--delete-keys"
	label := "Delete public key"
	if withSecret {
		option = "--delete-secret-and-public-keys"
		label = "Delete secret and public key"
	}
	return Command{
		label:    label,
		options:  []string{"--yes", option},
		operands: []string{fpr},
	}
}

// QuickSetExpireCommand changes a primary key's expiry, or a single subkey's
// when subkeyFpr is set.
func QuickSetExpireCommand(fpr, expiry, subkeyFpr string) Command {
	label := "Set primary key expiration"
	operands := []string{fpr, expiry}
	if subkeyFpr != "" {
		label = "Set subkey expiration"
		operands = append(operands, subkeyFpr)
	}
	return Command{label: label, options: []string{"--quick-set-expire"}, operands: operands}
}

// QuickSetOwnertrustCommand sets ownertrust on gpg 2.4+ using the word form
// (--quick-set-ownertrust rejects numbers).
func QuickSetOwnertrustCommand(fpr string, trust Ownertrust) Command {
	return Command{
		label:    "Set owner trust",
		options:  []string{"--quick-set-ownertrust"},
		operands: []string{fpr, trust.Word()},
	}
}

// ImportOwnertrustCommand sets ownertrust on gpg 2.2/2.3 via the ownertrust
// file format ("FPR:N:") on stdin.
func ImportOwnertrustCommand(fpr string, trust Ownertrust) Command {
	return Command{
		label:   "Set owner trust",
		options: []string{"--import-ownertrust"},
		stdin:   strings.NewReader(fpr + ":" + strconv.Itoa(int(trust)) + ":\n"),
	}
}

// ImportPreviewCommand shows what --import would import without changing the
// keyring; the keys arrive as a --with-colons listing on stdout.
func ImportPreviewCommand() Command {
	return Command{
		label:   "Preview keys to import",
		options: []string{"--with-colons", "--import-options", "show-only", "--import"},
	}
}

// ImportCommand imports keys from stdin.
func ImportCommand() Command {
	return Command{label: "Import keys", options: []string{"--import"}}
}

// GenRevokeCommand writes an ASCII-armored revocation certificate for fpr to
// stdout. It runs without --batch (gpg refuses --gen-revoke in batch mode),
// answering gpg's prompts from the status stream; reasonCode is one of the
// Revoke* constants, description is an optional single line.
func GenRevokeCommand(fpr string, reasonCode int, description string) (Command, error) {
	answers, err := GenRevokeAnswers(reasonCode, description)
	if err != nil {
		return Command{}, err
	}
	return Command{
		label:    "Create revocation certificate",
		options:  []string{"--gen-revoke"},
		operands: []string{fpr},
		answers:  answers,
	}, nil
}

// VersionCommand prints gpg's version banner.
func VersionCommand() Command {
	return Command{label: "Show gpg version", options: []string{"--version"}}
}

// DumpOptionsCommand lists every option this gpg build understands.
func DumpOptionsCommand() Command {
	return Command{label: "List supported gpg options", options: []string{"--dump-options"}}
}

// ListKeysCommand lists public keys, or secret keys when secret is set, in colon format.
func ListKeysCommand(secret bool) Command {
	if secret {
		return Command{label: "List secret keys", options: append(listKeyOptions(), "--list-secret-keys")}
	}
	return Command{label: "List public keys", options: append(listKeyOptions(), "--list-keys")}
}

func listKeyOptions() []string {
	return []string{"--with-colons", "--with-fingerprint", "--with-subkey-fingerprint"}
}

// ExportOwnertrustCommand prints the trust database's ownertrust values
// ("FPR:N:" lines); unlike the colon listing it is exact on gpg 2.2.
func ExportOwnertrustCommand() Command {
	return Command{label: "Read owner trust", options: []string{"--export-ownertrust"}}
}
