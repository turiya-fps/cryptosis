package fetch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetReturnsBody(t *testing.T) {
	body := "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	data, err := New(server.Client().Transport).Get(context.Background(), server.URL+"/key.asc")

	if err != nil || string(data) != body {
		t.Fatalf("Get = %q, %v", data, err)
	}
}

func TestGetRejectsNonHTTPSAndCredentials(t *testing.T) {
	for _, raw := range []string{"http://example.org/k", "ftp://example.org/k", "https://user:pw@example.org/k", "/relative", "file:///etc/passwd"} {
		if _, err := New(nil).Get(context.Background(), raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestGetRefusesRedirectToHTTP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.org/key.asc", http.StatusFound)
	}))
	defer server.Close()

	_, err := New(server.Client().Transport).Get(context.Background(), server.URL)

	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("err = %v, want redirect refusal", err)
	}
}

func TestGetRejectsOversizedBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), MaxBytes+1))
	}))
	defer server.Close()

	_, err := New(server.Client().Transport).Get(context.Background(), server.URL)

	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestGetRejectsNonOKStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()

	_, err := New(server.Client().Transport).Get(context.Background(), server.URL)

	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, want 404 error", err)
	}
}
