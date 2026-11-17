package gpg

import "slices"

// PacketKind classifies binary (unarmored) OpenPGP data by its first packet.
type PacketKind int

const (
	// PacketNone means the data does not start with a recognized OpenPGP packet.
	PacketNone PacketKind = iota
	// PacketEncrypted is an encrypted message: it starts with a public-key or
	// symmetric-key encrypted session key packet.
	PacketEncrypted
	// PacketSignature starts with a signature packet: a detached signature (or
	// a revocation certificate).
	PacketSignature
	// PacketSignedData is a signed message: one-pass signature, compressed or
	// literal data first (gpg --sign output).
	PacketSignedData
	// PacketKey is a transferable public or secret key.
	PacketKey
)

// Packet tags (RFC 9580 §5).
const (
	tagPKESK      = 1
	tagSignature  = 2
	tagSKESK      = 3
	tagOnePass    = 4
	tagSecretKey  = 5
	tagPublicKey  = 6
	tagCompressed = 8
	tagLiteral    = 11
)

// DetectPacket classifies data by its first OpenPGP packet header (RFC 9580
// §4.2, old and new format). It is a heuristic for labelling files: arbitrary
// binary data can start with matching bytes. Session key packets also need a
// known version byte, which cuts false positives for the encrypted case;
// v5 covers LibrePGP output from GnuPG 2.3+.
func DetectPacket(data []byte) PacketKind {
	tag, body, ok := firstPacket(data)
	if !ok {
		return PacketNone
	}
	switch tag {
	case tagPKESK:
		if versionIn(body, 3, 5, 6) {
			return PacketEncrypted
		}
		return PacketNone
	case tagSKESK:
		if versionIn(body, 4, 5, 6) {
			return PacketEncrypted
		}
		return PacketNone
	case tagSignature:
		return PacketSignature
	case tagOnePass, tagCompressed, tagLiteral:
		return PacketSignedData
	case tagSecretKey, tagPublicKey:
		return PacketKey
	default:
		return PacketNone
	}
}

// firstPacket returns the first packet's tag and the bytes after its header
// (the body start; possibly empty if data is short).
func firstPacket(data []byte) (tag int, body []byte, ok bool) {
	if len(data) == 0 || data[0]&0x80 == 0 {
		return 0, nil, false
	}
	header := data[0]
	rest := data[1:]
	if header&0x40 == 0 { // old format: tag in bits 5-2, length type in bits 1-0
		tag = int(header>>2) & 0x0F
		lengthBytes := [4]int{1, 2, 4, 0}[header&0x03] // 3 = indeterminate length
		return tag, skip(rest, lengthBytes), tag != 0
	}
	tag = int(header & 0x3F) // new format
	if len(rest) == 0 {
		return tag, nil, tag != 0
	}
	switch first := rest[0]; {
	case first < 192: // one-octet length
		return tag, skip(rest, 1), tag != 0
	case first < 224: // two-octet length
		return tag, skip(rest, 2), tag != 0
	case first == 255: // five-octet length
		return tag, skip(rest, 5), tag != 0
	default: // partial body length (one octet)
		return tag, skip(rest, 1), tag != 0
	}
}

func skip(data []byte, n int) []byte {
	if n >= len(data) {
		return nil
	}
	return data[n:]
}

// versionIn reports whether the body's first byte (the packet version) is one
// of versions; an absent body (truncated data) does not match.
func versionIn(body []byte, versions ...byte) bool {
	return len(body) > 0 && slices.Contains(versions, body[0])
}
