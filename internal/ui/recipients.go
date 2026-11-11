package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

// recipientStatus classifies a public key as an encryption recipient.
type recipientStatus int

const (
	recipientOK         recipientStatus = iota
	recipientUnverified                 // gpg would refuse without --trust-model always
	recipientBlocked                    // never selectable: expired, revoked, or unusable
)

// recipient is one candidate key for encryption.
type recipient struct {
	key    gpg.Key
	status recipientStatus
	reason string // why the key is blocked, when it is
}

// classifyRecipient applies the encryption policy: keys that are expired,
// revoked, disabled or have no usable encryption key are never offered;
// keys whose validity gpg cannot establish ("-", q, n, o) are unverified and
// need the allow-unverified-recipients setting plus a per-operation confirm.
func classifyRecipient(key gpg.Key, now time.Time) recipient {
	entry := recipient{key: key}
	blocked := func(reason string) recipient {
		entry.status = recipientBlocked
		entry.reason = reason
		return entry
	}
	switch key.Validity {
	case "r":
		return blocked("revoked")
	case "e":
		return blocked("expired")
	case "d":
		return blocked("disabled")
	case "i":
		return blocked("invalid")
	}
	if !key.Expires.IsZero() && now.After(key.Expires) {
		return blocked("expired")
	}
	if !hasUsableEncryptionKey(key, now) {
		return blocked("no usable encryption (sub)key")
	}
	switch key.Validity {
	case "m", "f", "u":
		entry.status = recipientOK
	default: // "-", "q", "n", "o" and anything unrecognized
		entry.status = recipientUnverified
	}
	return entry
}

// hasUsableEncryptionKey reports whether the key itself or a subkey can
// encrypt now. Capability letters are lowercase for a key's own uses; the
// uppercase E on a primary is only gpg's whole-key summary and does not count.
func hasUsableEncryptionKey(key gpg.Key, now time.Time) bool {
	material := []gpg.KeyMaterial{key.KeyMaterial}
	material = append(material, key.Subkeys...)
	for _, m := range material {
		if !strings.ContainsRune(m.Capabilities, 'e') {
			continue
		}
		expired := !m.Expires.IsZero() && now.After(m.Expires)
		if m.Validity == "r" || m.Validity == "e" || m.Validity == "d" || m.Validity == "i" || expired {
			continue
		}
		return true
	}
	return false
}

// weakAlgoNote tags weak algorithms in the picker (analysis: warn on weak keys).
func weakAlgoNote(key gpg.Key) string {
	isWeakRSA := strings.HasPrefix(key.AlgoName(), "RSA") && key.Length < 3072
	if key.Algo == 17 || key.Algo == 16 || isWeakRSA { // DSA, Elgamal
		return " [weak: " + sanitize.Line(key.AlgoName()) + "]"
	}
	return ""
}

// encryptionRequest is a resolved recipient set ready for one EncryptCommand.
type encryptionRequest struct {
	fprs        []string
	trustAlways bool // an unverified recipient was explicitly allowed
}

// chooseRecipients lets the user select recipients under the encryption
// policy. ok is false when nothing will be encrypted (cancel or refusal).
func (a *App) chooseRecipients(ctx context.Context) (encryptionRequest, bool, error) {
	ring, err := a.loadKeyring(ctx)
	if err != nil {
		return encryptionRequest{}, false, err
	}
	now := time.Now()
	var selectable []recipient
	for _, key := range ring.keys {
		entry := classifyRecipient(key, now)
		if entry.status == recipientBlocked {
			fmt.Fprintf(a.out, "Skipping %s (%s): %s\n",
				key.KeyID, truncateRunes(primaryUserID(key), tableUserIDRunes), entry.reason)
			continue
		}
		selectable = append(selectable, entry)
	}
	if len(selectable) == 0 {
		fmt.Fprintln(a.out, "No usable encryption keys in the keyring.")
		return encryptionRequest{}, false, nil
	}

	chosen, err := a.pickRecipients(selectable)
	if err != nil || len(chosen) == 0 {
		return encryptionRequest{}, false, ignoreAbort(err)
	}
	return a.resolveUnverified(chosen)
}

func (a *App) pickRecipients(candidates []recipient) ([]recipient, error) {
	byFingerprint := make(map[string]recipient, len(candidates))
	options := make([]huh.Option[string], 0, len(candidates))
	for _, entry := range candidates {
		byFingerprint[entry.key.Fingerprint] = entry
		options = append(options, huh.NewOption(recipientLabel(entry), entry.key.Fingerprint))
	}
	var selectedFprs []string
	picker := huh.NewMultiSelect[string]().
		Title("Recipients (space to mark, / to filter)").
		Options(options...).
		Height(min(len(options)+4, 15)).
		Value(&selectedFprs)
	if err := a.newForm(huh.NewGroup(picker)).Run(); err != nil {
		return nil, err
	}
	selected := make([]recipient, 0, len(selectedFprs))
	for _, fpr := range selectedFprs {
		selected = append(selected, byFingerprint[fpr])
	}
	return selected, nil
}

func recipientLabel(entry recipient) string {
	key := entry.key
	label := truncateRunes(primaryUserID(key), pickerUserIDRunes) + "  " + key.KeyID
	if entry.status == recipientUnverified {
		label += "  [unverified]"
	}
	label += weakAlgoNote(key)
	return label
}

// resolveUnverified enforces the unverified-recipient policy: refuse (with a
// pointer to the setting), or confirm and mark the command for
// --trust-model always.
func (a *App) resolveUnverified(chosen []recipient) (encryptionRequest, bool, error) {
	request := encryptionRequest{trustAlways: false}
	var unverified []recipient
	for _, entry := range chosen {
		request.fprs = append(request.fprs, entry.key.Fingerprint)
		if entry.status == recipientUnverified {
			unverified = append(unverified, entry)
		}
	}
	if len(unverified) == 0 {
		return request, true, nil
	}

	fmt.Fprintln(a.out, "You selected keys gpg has no assurance about:")
	for _, entry := range unverified {
		fmt.Fprintf(a.out, "  %s  %s\n", entry.key.KeyID, truncateRunes(primaryUserID(entry.key), pickerUserIDRunes))
	}
	if !a.Config.AllowUnverifiedRecipients {
		fmt.Fprintln(a.out, "Refusing: an unverified key may belong to someone else.")
		fmt.Fprintln(a.out, "To encrypt anyway, enable Settings → Allow unverified recipients, then confirm per operation.")
		return encryptionRequest{}, false, nil
	}
	confirmed, err := a.askConfirm("Encrypt to these unverified keys anyway? (--trust-model always)", false)
	if err != nil || !confirmed {
		fmt.Fprintln(a.out, "Cancelled.")
		return encryptionRequest{}, false, ignoreAbort(err)
	}
	request.trustAlways = true
	return request, true, nil
}

// pickSigningKey returns the fingerprint to sign with: the configured default
// signing key when set, otherwise the user's choice ("" = gpg's default).
// errBack cancels the whole operation.
func (a *App) pickSigningKey(ctx context.Context) (string, error) {
	if a.Config.DefaultSigningKey != "" {
		return a.Config.DefaultSigningKey, nil
	}
	ring, err := a.loadKeyring(ctx)
	if err != nil {
		return "", err
	}
	const backValue = "back"
	options := []huh.Option[string]{huh.NewOption("gpg's default key", "")}
	for _, key := range ring.keys {
		if !ring.hasSecret[key.Fingerprint] {
			continue
		}
		options = append(options, huh.NewOption(keyPickerLabel(key, true), key.Fingerprint))
	}
	options = append(options, huh.NewOption("Back", backValue))

	var fpr string
	menu := huh.NewSelect[string]().Title("Sign with").Options(options...).Height(min(len(options)+2, 15)).Value(&fpr)
	if err := a.newForm(huh.NewGroup(menu)).Run(); err != nil {
		return "", err
	}
	if fpr == backValue {
		return "", errBack
	}
	return fpr, nil
}

// askSignKey confirms optional signing and resolves the signing key; empty
// fpr with ok=false means "do not sign", errBack cancels the operation.
func (a *App) askSignKey(ctx context.Context, title string) (signFpr string, sign bool, err error) {
	sign, err = a.askConfirm(title, false)
	if err != nil || !sign {
		return "", false, ignoreAbort(err)
	}
	signFpr, err = a.pickSigningKey(ctx)
	if errors.Is(err, errBack) {
		return "", false, nil
	}
	return signFpr, true, err
}
