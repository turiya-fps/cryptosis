package keyserver

import (
	"context"
	"crypto/sha1" //nolint:gosec // WKD mandates SHA-1 for the local-part hash (a file name, not security)
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// zBase32Alphabet is the z-base-32 alphabet used by WKD (per RFC 6189
// section 5.1.6), MSB-first, no padding.
const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// ZBase32 encodes b with the z-base-32 alphabet.
func ZBase32(b []byte) string {
	var out []byte
	bits := 0
	value := uint(0)
	for _, byteValue := range b {
		value = value<<8 | uint(byteValue)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, zBase32Alphabet[(value>>bits)&0x1f])
		}
	}
	if bits > 0 {
		out = append(out, zBase32Alphabet[(value<<(5-bits))&0x1f])
	}
	return string(out)
}

// WKDLocalPart maps an email local part the way WKD requires: upper-case
// ASCII mapped to lower-case (non-ASCII unchanged), SHA-1 hashed, z-base-32
// encoded. The result is 32 characters.
func WKDLocalPart(localPart string) string {
	sum := sha1.Sum([]byte(asciiLower(localPart))) //nolint:gosec // not security: WKD maps the local-part to a file name
	return ZBase32(sum[:])
}

// SplitEmail splits an address into local part and domain. The domain is
// mapped to lower-case and must be plain ASCII (punycode for international
// domains is the caller's business); the local part is returned unchanged.
func SplitEmail(address string) (local, domain string, err error) {
	at := strings.LastIndex(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "", "", fmt.Errorf("%q is not an email address", address)
	}
	local = strings.TrimSpace(address[:at])
	domain = asciiLower(strings.TrimSpace(address[at+1:]))
	if local == "" || domain == "" || !strings.Contains(domain, ".") {
		return "", "", fmt.Errorf("%q is not a usable email address", address)
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] <= ' ' || domain[i] >= 0x7f || strings.ContainsRune("/\\?#@:", rune(domain[i])) {
			return "", "", fmt.Errorf("%q has an unusable domain part", address)
		}
	}
	if strings.ContainsFunc(local, func(r rune) bool { return r == ' ' || r == '\t' }) {
		return "", "", fmt.Errorf("%q has an unusable local part", address)
	}
	return local, domain, nil
}

func asciiLower(s string) string {
	out := []byte(s)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + 'a' - 'A'
		}
	}
	return string(out)
}

// GetWKD fetches the key an email address's own domain publishes via WKD,
// trying the advanced method (openpgpkey.<domain>) before the direct one.
// The direct method is only tried when the advanced host does not resolve
// (draft-koch-openpgp-webkey-service: a non-responding server is not a
// reason to fall back). Both URLs carry the unchanged local part as the l
// parameter. A domain publishing WKD but not this key returns ErrNotFound.
func (c *Client) GetWKD(ctx context.Context, address string) ([]byte, error) {
	local, domain, err := SplitEmail(address)
	if err != nil {
		return nil, err
	}
	hu := WKDLocalPart(local)
	l := url.Values{}
	l.Set("l", local)
	query := l.Encode()

	advanced := fmt.Sprintf("https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s?%s", domain, domain, hu, query)
	data, err := c.fetch.Get(ctx, advanced)
	if err == nil {
		return data, nil
	}
	if isNotFound(err) {
		return nil, ErrNotFound
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		return nil, fmt.Errorf("WKD lookup: %w", err)
	}
	// The advanced host does not exist: the draft allows the direct method.
	direct := fmt.Sprintf("https://%s/.well-known/openpgpkey/hu/%s?%s", domain, hu, query)
	data, directErr := c.fetch.Get(ctx, direct)
	if directErr == nil {
		return data, nil
	}
	if isNotFound(directErr) {
		return nil, ErrNotFound
	}
	return nil, errors.Join(err, directErr)
}
