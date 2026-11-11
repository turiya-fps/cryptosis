// Package fetch downloads small public documents (OpenPGP keys) over HTTPS
// only, with a size cap and timeout. Redirects must stay on HTTPS.
package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// MaxBytes caps a download; generous for keys with many signatures.
	MaxBytes     = 8 << 20
	timeout      = 30 * time.Second
	maxRedirects = 5
)

// ErrTooLarge is returned when the response body exceeds MaxBytes.
var ErrTooLarge = fmt.Errorf("download larger than %d bytes", MaxBytes)

// StatusError reports a non-200 answer from the server.
type StatusError struct {
	Code   int
	Status string
}

func (e *StatusError) Error() string { return "server answered " + e.Status }

// Client fetches HTTPS URLs.
type Client struct {
	http *http.Client
}

// New returns a Client using transport, or http.DefaultTransport when nil.
func New(transport http.RoundTripper) *Client {
	return &Client{http: &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}}
}

// ValidateURL accepts only absolute https:// URLs without credentials.
func ValidateURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	isPlainHTTPS := parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
	if !isPlainHTTPS {
		return nil, errors.New("only https:// URLs without credentials are allowed")
	}
	return parsed, nil
}

// Get downloads rawURL and returns the body.
func (c *Client) Get(ctx context.Context, rawURL string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, rawURL, "", nil)
}

// Post uploads body to rawURL and returns the response body. Redirects must
// preserve the method and stay on HTTPS.
func (c *Client) Post(ctx context.Context, rawURL, contentType string, body []byte) ([]byte, error) {
	return c.do(ctx, http.MethodPost, rawURL, contentType, bytes.NewReader(body))
}

func (c *Client) do(ctx context.Context, method, rawURL, contentType string, body io.Reader) ([]byte, error) {
	parsed, err := ValidateURL(rawURL)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: response.StatusCode, Status: response.Status}
	}
	return readCapped(response.Body)
}

func readCapped(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

func checkRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if request.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-HTTPS URL %s", request.URL.Redacted())
	}
	return nil
}
