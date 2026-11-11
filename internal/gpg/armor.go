package gpg

import "bytes"

// ArmorKind identifies an ASCII-armored OpenPGP block by its header line.
type ArmorKind int

const (
	// ArmorNone means no armored OpenPGP block was recognized.
	ArmorNone ArmorKind = iota
	// ArmorMessage is "-----BEGIN PGP MESSAGE-----": encrypted and/or
	// compressed/inline-signed data (decrypt reports any signature).
	ArmorMessage
	// ArmorSignature is "-----BEGIN PGP SIGNATURE-----": a detached signature.
	ArmorSignature
	// ArmorSignedMessage is "-----BEGIN PGP SIGNED MESSAGE-----": cleartext
	// signature (the message text is inside the same file).
	ArmorSignedMessage
	// ArmorPublicKey is "-----BEGIN PGP PUBLIC KEY BLOCK-----".
	ArmorPublicKey
	// ArmorPrivateKey is "-----BEGIN PGP PRIVATE KEY BLOCK-----".
	ArmorPrivateKey
)

// detectWindow bounds how far into a file the armor header is searched: a few
// leading lines are tolerated, but the header must appear near the start.
const detectWindow = 8 << 10

// DetectArmor classifies data by the first "-----BEGIN PGP" header line found
// in the opening bytes. Binary data and unrecognized files return ArmorNone.
func DetectArmor(data []byte) ArmorKind {
	window := data
	if len(window) > detectWindow {
		window = window[:detectWindow]
	}
	for _, line := range bytes.Split(window, []byte("\n")) {
		kind, found := armorKindOfLine(bytes.TrimSuffix(line, []byte("\r")))
		if found {
			return kind
		}
	}
	return ArmorNone
}

func armorKindOfLine(line []byte) (ArmorKind, bool) {
	rest, found := bytes.CutPrefix(line, []byte("-----BEGIN PGP "))
	if !found {
		return ArmorNone, false
	}
	rest, found = bytes.CutSuffix(rest, []byte("-----"))
	if !found {
		return ArmorNone, false
	}
	switch string(rest) {
	case "MESSAGE":
		return ArmorMessage, true
	case "SIGNATURE":
		return ArmorSignature, true
	case "SIGNED MESSAGE":
		return ArmorSignedMessage, true
	case "PUBLIC KEY BLOCK":
		return ArmorPublicKey, true
	case "PRIVATE KEY BLOCK":
		return ArmorPrivateKey, true
	default:
		return ArmorNone, false
	}
}
