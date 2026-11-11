// Package keyserver fetches and uploads OpenPGP public keys over HTTPS:
// a VKS (e.g. keys.openpgp.org), HKP lookup endpoints, and WKD discovery.
// Nothing is imported into the keyring here; callers preview the returned
// bytes and import through the normal flow.
package keyserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/turiya-fps/cryptosis/internal/fetch"
)

// ErrNotFound reports that the server does not have the requested key; the
// caller may fall back to another mechanism.
var ErrNotFound = errors.New("key not found")

// ErrNoSearch reports a keyserver without a search interface.
var ErrNoSearch = errors.New("this keyserver does not support search; fetch by email or fingerprint instead")

// ErrExactSearchOnly reports a keyserver that rejected the search term
// because it only answers exact queries (keys.openpgp.org: a full email
// address, fingerprint or key ID; anything else gets 400).
var ErrExactSearchOnly = errors.New("this keyserver only answers exact searches: a full email address, fingerprint or key ID")

// Client talks to one keyserver (VKS and HKP endpoints) and to WKD hosts.
type Client struct {
	base  *url.URL
	fetch *fetch.Client
}

// New returns a Client for baseURL, an https:// URL, using transport (or the
// default) for its connections.
func New(baseURL string, transport http.RoundTripper) (*Client, error) {
	base, err := fetch.ValidateURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("keyserver: %w", err)
	}
	return &Client{base: base, fetch: fetch.New(transport)}, nil
}

// URL is the keyserver's base URL.
func (c *Client) URL() string { return c.base.String() }

// GetByFingerprint fetches a key by fingerprint (or 16-hex long key ID) from
// the configured keyserver: VKS first (by-keyid for key IDs, since
// by-fingerprint answers 400 to them), then HKP op=get.
func (c *Client) GetByFingerprint(ctx context.Context, query string) ([]byte, error) {
	endpoint := "by-fingerprint"
	if len(query) == 16 {
		endpoint = "by-keyid"
	}
	data, err := c.fetch.Get(ctx, c.base.JoinPath("vks", "v1", endpoint, query).String())
	if err == nil {
		return data, nil
	}
	if !isNotFound(err) {
		return nil, err
	}
	return c.hkpGet(ctx, "0x"+query)
}

// GetByEmail fetches a key by exact email address from the configured
// keyserver: VKS first, then HKP op=get.
func (c *Client) GetByEmail(ctx context.Context, email string) ([]byte, error) {
	data, err := c.fetch.Get(ctx, c.base.JoinPath("vks", "v1", "by-email", email).String())
	if err == nil {
		return data, nil
	}
	if !isNotFound(err) {
		return nil, err
	}
	return c.hkpGet(ctx, email)
}

// EmailLookup is the outcome of GetForEmail.
type EmailLookup struct {
	Data   []byte
	ViaWKD bool  // the address's own domain published the key
	WKDErr error // WKD failed for a reason other than "no key"; the keyserver was asked instead
}

// GetForEmail fetches the key for an email address: WKD (the recipient's own
// domain publishes it), falling back to the configured keyserver (which does
// not verify addresses). Like gpg's --auto-key-locate, any WKD failure moves
// on to the keyserver; a failure other than "no key" is kept in WKDErr.
func (c *Client) GetForEmail(ctx context.Context, email string) (EmailLookup, error) {
	data, err := c.GetWKD(ctx, email)
	if err == nil {
		return EmailLookup{Data: data, ViaWKD: true}, nil
	}
	var lookup EmailLookup
	if !errors.Is(err, ErrNotFound) {
		lookup.WKDErr = err
	}
	lookup.Data, err = c.GetByEmail(ctx, email)
	return lookup, err
}

// hkpGet fetches a key via HKP op=get (machine-readable).
func (c *Client) hkpGet(ctx context.Context, search string) ([]byte, error) {
	lookup := *c.base
	lookup.Path += "/pks/lookup"
	q := url.Values{}
	q.Set("op", "get")
	q.Set("options", "mr")
	q.Set("search", search)
	lookup.RawQuery = q.Encode()
	data, err := c.fetch.Get(ctx, lookup.String())
	if err != nil && isNotFound(err) {
		return nil, ErrNotFound
	}
	return data, err
}

func isNotFound(err error) bool {
	var status *fetch.StatusError
	return errors.As(err, &status) && (status.Code == http.StatusNotFound || status.Code == http.StatusNotImplemented)
}
