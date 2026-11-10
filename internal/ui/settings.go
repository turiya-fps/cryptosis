package ui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"charm.land/huh/v2"

	"github.com/turiya-fps/cryptosis/internal/config"
	"github.com/turiya-fps/cryptosis/internal/gpg"
	"github.com/turiya-fps/cryptosis/internal/sanitize"
)

type settingID int

const (
	settingGPGPath settingID = iota
	settingKeyserver
	settingClipboardClear
	settingKeyAlgo
	settingKeyExpiry
	settingSubkeyExpiry
	settingOwnertrustSource
	settingDefaultSigningKey
	settingArmorFiles
	settingAccessible
	settingUnverifiedRecipients
	settingReset
	settingBack
)

// runSettings lets the user edit one setting at a time; each change is
// validated and saved immediately.
func (a *App) runSettings() error {
	for {
		choice, err := a.chooseSetting()
		if errors.Is(err, huh.ErrUserAborted) || choice == settingBack {
			return nil
		}
		if err != nil {
			return err
		}

		updated, changed, err := a.editSetting(choice)
		if errors.Is(err, huh.ErrUserAborted) || !changed {
			continue
		}
		if err != nil {
			return err
		}
		if err := a.saveConfig(updated); err != nil {
			a.printError(err)
		}
	}
}

func (a *App) chooseSetting() (settingID, error) {
	c := a.Config
	options := []huh.Option[settingID]{
		huh.NewOption("gpg binary: "+orDefault(c.GPGPath, "from PATH"), settingGPGPath),
		huh.NewOption("Keyserver: "+c.Keyserver, settingKeyserver),
		huh.NewOption("Clipboard auto-clear: "+describeClipboardClear(c.ClipboardClearSeconds), settingClipboardClear),
		huh.NewOption("New key algorithm: "+c.KeyAlgo, settingKeyAlgo),
		huh.NewOption("New key expiry: "+c.KeyExpiry, settingKeyExpiry),
		huh.NewOption("New encryption subkey expiry: "+describeSubkeyExpiry(c.SubkeyExpiryMatchesPrimary), settingSubkeyExpiry),
		huh.NewOption("Owner trust shown from: "+describeOwnertrustSource(c.OwnertrustFromTrustDB), settingOwnertrustSource),
		huh.NewOption("Default signing key: "+orDefault(c.DefaultSigningKey, "gpg default"), settingDefaultSigningKey),
		huh.NewOption("Armor (.asc) file output: "+onOff(c.ArmorFiles), settingArmorFiles),
		huh.NewOption("Accessible mode: "+onOff(c.AccessibleMode), settingAccessible),
		huh.NewOption("Allow unverified recipients: "+onOff(c.AllowUnverifiedRecipients), settingUnverifiedRecipients),
		huh.NewOption("Reset all to defaults", settingReset),
		huh.NewOption("Back", settingBack),
	}
	for i := range options {
		options[i].Key = sanitize.Line(options[i].Key)
	}

	var choice settingID
	menu := huh.NewSelect[settingID]().Title("Settings").Description(sanitize.Line(a.ConfigPath)).Options(options...).Value(&choice)
	err := a.newForm(huh.NewGroup(menu)).Run()
	return choice, err
}

// editSetting returns a modified copy of the config; changed is false when nothing changed.
func (a *App) editSetting(id settingID) (config.Config, bool, error) {
	updated := a.Config
	var err error
	switch id {
	case settingGPGPath:
		err = a.inputString("gpg binary path", "Absolute path; empty uses gpg from PATH. Applies on next start.", &updated.GPGPath, validateGPGPath)
	case settingKeyserver:
		err = a.inputString("Keyserver URL", "https:// only.", &updated.Keyserver, validateField(func(c *config.Config, v string) { c.Keyserver = v }))
	case settingClipboardClear:
		err = a.inputClipboardClear(&updated.ClipboardClearSeconds)
	case settingKeyAlgo:
		err = a.selectKeyAlgo(&updated.KeyAlgo)
	case settingKeyExpiry:
		err = a.inputString("New key expiry", "e.g. 2y, 18m, 6w, 30d or never.", &updated.KeyExpiry, validateField(func(c *config.Config, v string) { c.KeyExpiry = v }))
	case settingSubkeyExpiry:
		updated.SubkeyExpiryMatchesPrimary, err = a.askConfirm("Give new encryption subkeys the primary key's expiry? (gpg's default: never expires)", updated.SubkeyExpiryMatchesPrimary)
	case settingOwnertrustSource:
		updated.OwnertrustFromTrustDB, err = a.askConfirm("Read owner trust from the trust database? (one extra gpg call; exact on gpg 2.2)", updated.OwnertrustFromTrustDB)
	case settingDefaultSigningKey:
		err = a.inputString("Default signing key", "Full fingerprint; empty uses gpg's default.", &updated.DefaultSigningKey, validateFingerprintOrEmpty)
	case settingArmorFiles:
		updated.ArmorFiles, err = a.askConfirm("Write encrypted/signed files as ASCII armor (.asc)?", updated.ArmorFiles)
	case settingAccessible:
		updated.AccessibleMode, err = a.askConfirm("Use accessible mode (plain prompts, screen-reader friendly)?", updated.AccessibleMode)
	case settingUnverifiedRecipients:
		updated.AllowUnverifiedRecipients, err = a.confirmUnverifiedRecipients(updated.AllowUnverifiedRecipients)
	case settingReset:
		updated, err = a.confirmReset()
	}
	return updated, err == nil && updated != a.Config, err
}

func (a *App) saveConfig(updated config.Config) error {
	if err := config.Save(a.ConfigPath, updated); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	a.Config = updated
	fmt.Fprintln(a.out, "Saved.")
	return nil
}

func (a *App) inputString(title, description string, value *string, validate func(string) error) error {
	field := huh.NewInput().Title(title).Description(description).Value(value).Validate(validate)
	err := a.newForm(huh.NewGroup(field)).Run()
	*value = strings.TrimSpace(*value)
	return err
}

func (a *App) inputClipboardClear(seconds *int) error {
	text := strconv.Itoa(*seconds)
	validate := func(v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return errors.New("enter a whole number of seconds")
		}
		probe := config.Default()
		probe.ClipboardClearSeconds = n
		return probe.Validate()
	}
	if err := a.inputString("Clipboard auto-clear", "Seconds before cryptosis clears text it copied; 0 = off.", &text, validate); err != nil {
		return err
	}
	parsed, err := strconv.Atoi(text)
	if err != nil {
		return err
	}
	*seconds = parsed
	return nil
}

func (a *App) selectKeyAlgo(algo *string) error {
	field := huh.NewSelect[string]().
		Title("New key algorithm").
		Description("Passed to gpg --quick-generate-key.").
		Options(
			huh.NewOption("future-default (ed25519 + cv25519)", config.KeyAlgoFutureDefault),
			huh.NewOption("default (gpg's current default)", config.KeyAlgoDefault),
		).
		Value(algo)
	return a.newForm(huh.NewGroup(field)).Run()
}

func (a *App) confirmUnverifiedRecipients(current bool) (bool, error) {
	if current {
		return a.askConfirm("Keep allowing encryption to unverified keys?", true)
	}
	field := huh.NewConfirm().
		Title("Allow encryption to keys you have not verified?").
		Description("Each such encryption is still flagged and needs confirmation, and uses --trust-model always for that one command.\nAn unverified key may belong to someone else.").
		Affirmative("Allow").Negative("Keep blocked").
		Value(&current)
	err := a.newForm(huh.NewGroup(field)).Run()
	return current, err
}

func (a *App) confirmReset() (config.Config, error) {
	confirmed, err := a.askConfirm("Reset all settings to defaults?", false)
	if err != nil || !confirmed {
		return a.Config, err
	}
	return config.Default(), nil
}

func validateField(set func(*config.Config, string)) func(string) error {
	return func(v string) error {
		probe := config.Default()
		set(&probe, strings.TrimSpace(v))
		return probe.Validate()
	}
}

func validateGPGPath(v string) error {
	path := strings.TrimSpace(v)
	if path == "" {
		return nil
	}
	_, err := gpg.NewRunner(path, "")
	return err
}

func validateFingerprintOrEmpty(v string) error {
	fingerprint := strings.TrimSpace(v)
	if fingerprint == "" || gpg.IsFingerprint(fingerprint) {
		return nil
	}
	return errors.New("enter a full 40 or 64 character upper-case fingerprint")
}

func describeClipboardClear(seconds int) string {
	if seconds == 0 {
		return "off"
	}
	return fmt.Sprintf("%ds", seconds)
}

func describeSubkeyExpiry(matchesPrimary bool) string {
	if matchesPrimary {
		return "same as primary"
	}
	return "never (gpg default)"
}

func describeOwnertrustSource(fromTrustDB bool) string {
	if fromTrustDB {
		return "trust database"
	}
	return "key listing (gpg default)"
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}
