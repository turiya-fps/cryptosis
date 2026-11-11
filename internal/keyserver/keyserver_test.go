package keyserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testFpr = "DC647EAC8261132177DB2373BAC6DD0574D0C0E8"

// newServer starts a TLS test server. The returned client transport routes
// every request through the server (whatever host the URL names), so WKD
// lookups of test domains stay local; a request to the advanced WKD host of
// a domain whose direct host is served with noWkdAdvanced returns a DNS
// not-found error, exercising the fallback.
func newServer(t *testing.T, handler http.HandlerFunc, noWkdAdvanced bool) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		host := request.URL.Hostname()
		if noWkdAdvanced && strings.HasPrefix(host, "openpgpkey.") {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		toServer := request.Clone(context.Background())
		toServer.URL.Scheme = "https"
		toServer.URL.Host = server.Listener.Addr().String()
		response, err := server.Client().Transport.RoundTrip(toServer)
		if response != nil {
			response.Request = request
		}
		return response, err
	})
	client, err := New("https://keys.example", transport)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestGetByFingerprintVKS(t *testing.T) {
	var gotPath string
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, "armored key")
	}, false)
	data, err := client.GetByFingerprint(context.Background(), testFpr)
	if err != nil || string(data) != "armored key" {
		t.Fatalf("got %q, %v", data, err)
	}
	if want := "/vks/v1/by-fingerprint/" + testFpr; gotPath != want {
		t.Fatalf("requested %q, want %q", gotPath, want)
	}
}

func TestGetByFingerprintFallsBackToHKP(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vks/v1/by-fingerprint/" + testFpr:
			http.Error(w, "not found", http.StatusNotFound)
		case "/pks/lookup":
			if r.URL.Query().Get("op") != "get" || r.URL.Query().Get("search") != "0x"+testFpr {
				t.Errorf("unexpected query %v", r.URL.RawQuery)
			}
			fmt.Fprint(w, "hkp key")
		default:
			http.Error(w, "unexpected path", http.StatusBadRequest)
		}
	}, false)
	data, err := client.GetByFingerprint(context.Background(), testFpr)
	if err != nil || string(data) != "hkp key" {
		t.Fatalf("got %q, %v", data, err)
	}
}

func TestGetByEmailNotFound(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}, false)
	for _, fn := range []func(context.Context, string) ([]byte, error){
		client.GetByEmail,
		func(ctx context.Context, email string) ([]byte, error) { return client.GetByFingerprint(ctx, email) },
	} {
		if _, err := fn(context.Background(), "a@e.org"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	}
}

func TestSearchParsesMachineReadable(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pks/lookup" {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		q := r.URL.Query()
		if q.Get("op") != "index" || q.Get("options") != "mr" || q.Get("fingerprint") != "on" || q.Get("search") != "alice" {
			t.Errorf("unexpected query %v", r.URL.RawQuery)
		}
		fmt.Fprint(w, "info:1:1\n"+
			"pub:"+testFpr+":22:301:1672531200:1735689600:er\n"+
			"uid:Alice%20%3Calice@e.org%3E:1672531200:0:\n"+
			"uid:Alice%20Second:0:0:\n"+
			"pub:ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD:1:2048:1600000000:0:\n"+
			"uid:Bob%20%3Cbob@e.org%3E:1600000000:0:\n")
	}, false)
	results, err := client.Search(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	first := results[0]
	if first.Fingerprint != testFpr || first.AlgoID != 22 || first.Bits != 301 ||
		first.Created != 1672531200 || first.Expires != 1735689600 ||
		!first.Expired || !first.Revoked || first.Disabled {
		t.Fatalf("pub parsed wrong: %+v", first)
	}
	if len(first.UIDs) != 2 || first.UIDs[0] != "Alice <alice@e.org>" || first.UIDs[1] != "Alice Second" {
		t.Fatalf("uids parsed wrong: %q", first.UIDs)
	}
	if results[1].Fingerprint != "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD" || len(results[1].UIDs) != 1 {
		t.Fatalf("second result wrong: %+v", results[1])
	}
}

func TestSearchUnsupportedAndEmpty(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("search") {
		case "none":
			fmt.Fprint(w, "info:1:1\n")
		case "missing":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.Error(w, "not implemented", http.StatusNotImplemented)
		}
	}, false)
	if _, err := client.Search(context.Background(), "none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty listing: got %v, want ErrNotFound", err)
	}
	// HKP answers 404 when nothing matches (keys.openpgp.org does).
	if _, err := client.Search(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: got %v, want ErrNotFound", err)
	}
	if _, err := client.Search(context.Background(), "anything"); !errors.Is(err, ErrNoSearch) {
		t.Fatalf("501: got %v, want ErrNoSearch", err)
	}
}

func TestUploadAndRequestVerify(t *testing.T) {
	var uploadBody, verifyBody string
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/vks/v1/upload":
			uploadBody = string(body)
			fmt.Fprint(w, `{"token":"the-token"}`)
		case "/vks/v1/request-verify":
			verifyBody = string(body)
			fmt.Fprint(w, "{}")
		}
	}, false)
	token, err := client.Upload(context.Background(), "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n")
	if err != nil || token != "the-token" {
		t.Fatalf("Upload: %q, %v", token, err)
	}
	if !strings.Contains(uploadBody, "\"keymaterial\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\nabc\\n-----END PGP PUBLIC KEY BLOCK-----\\n\"") {
		t.Fatalf("upload body wrong: %q", uploadBody)
	}
	if err := client.RequestVerify(context.Background(), token, []string{"a@e.org"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verifyBody, `"token":"the-token"`) || !strings.Contains(verifyBody, `"addresses":["a@e.org"]`) {
		t.Fatalf("request-verify body wrong: %q", verifyBody)
	}
}

func TestWKDAdvancedBeforeDirect(t *testing.T) {
	requested := make([]string, 0, 4)
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.Host+r.URL.RequestURI())
		if strings.HasPrefix(r.Host, "openpgpkey.") {
			fmt.Fprint(w, "advanced key")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}, false)
	data, err := client.GetWKD(context.Background(), "Joe.Doe@Example.ORG")
	if err != nil || string(data) != "advanced key" {
		t.Fatalf("got %q, %v", data, err)
	}
	if len(requested) != 1 || requested[0] != "openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" {
		t.Fatalf("requested %q", requested)
	}
}

func TestWKDFallsBackToDirectOnDNSNotFound(t *testing.T) {
	requested := make([]string, 0, 4)
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.Host+r.URL.RequestURI())
		if strings.HasPrefix(r.Host, "openpgpkey.") {
			t.Errorf("advanced host should not have been reached")
		}
		fmt.Fprint(w, "direct key")
	}, true)
	data, err := client.GetWKD(context.Background(), "user@example.org")
	if err != nil || string(data) != "direct key" {
		t.Fatalf("got %q, %v", data, err)
	}
	wantDirect := "example.org/.well-known/openpgpkey/hu/" + WKDLocalPart("user") + "?l=user"
	if len(requested) != 1 || requested[0] != wantDirect {
		t.Fatalf("requested %q", requested)
	}
}

func TestWKDNotFound(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}, false)
	if _, err := client.GetWKD(context.Background(), "user@example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGetForEmailPrefersWKD(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "openpgpkey.") {
			fmt.Fprint(w, "wkd key")
			return
		}
		fmt.Fprint(w, "keyserver key")
	}, false)
	lookup, err := client.GetForEmail(context.Background(), "user@example.org")
	if err != nil || string(lookup.Data) != "wkd key" || !lookup.ViaWKD || lookup.WKDErr != nil {
		t.Fatalf("got %+v, %v", lookup, err)
	}
}

// A broken WKD host (here: 500) must not stop the lookup; the keyserver is
// asked and the WKD failure is reported alongside.
func TestGetForEmailFallsBackWhenWKDFails(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "openpgpkey.") {
			http.Error(w, "broken", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "keyserver key")
	}, false)
	lookup, err := client.GetForEmail(context.Background(), "user@example.org")
	if err != nil || string(lookup.Data) != "keyserver key" || lookup.ViaWKD || lookup.WKDErr == nil {
		t.Fatalf("got %+v, %v", lookup, err)
	}
}

func TestGetByKeyIDUsesVKSByKeyID(t *testing.T) {
	var gotPath string
	client, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, "armored key")
	}, false)
	keyID := testFpr[24:]
	if _, err := client.GetByFingerprint(context.Background(), keyID); err != nil {
		t.Fatal(err)
	}
	if want := "/vks/v1/by-keyid/" + keyID; gotPath != want {
		t.Fatalf("requested %q, want %q", gotPath, want)
	}
}

// keys.openpgp.org answers 400 to non-exact HKP index searches.
func TestSearchBadRequestIsExactOnly(t *testing.T) {
	client, _ := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}, false)
	if _, err := client.Search(context.Background(), "gnupg"); !errors.Is(err, ErrExactSearchOnly) {
		t.Fatalf("got %v, want ErrExactSearchOnly", err)
	}
}

func TestWKDLocalPartMatchesDraft(t *testing.T) {
	// draft-koch-openpgp-webkey-service: Joe.Doe@Example.ORG hashes to
	// iy9q119eutrkn8s1mk4r39qejnbu3n5q (ASCII lower-cased before hashing).
	if got := WKDLocalPart("Joe.Doe"); got != "iy9q119eutrkn8s1mk4r39qejnbu3n5q" {
		t.Fatalf("WKDLocalPart(Joe.Doe) = %q", got)
	}
	if got := len(WKDLocalPart("user")); got != 32 {
		t.Fatalf("length %d, want 32", got)
	}
}

func TestSplitEmail(t *testing.T) {
	local, domain, err := SplitEmail("Joe.Doe@Example.COM")
	if err != nil || local != "Joe.Doe" || domain != "example.com" {
		t.Fatalf("got %q %q %v", local, domain, err)
	}
	for _, bad := range []string{"", "no-at", "@e.org", "a@", "a b@e.org", "a@e org", "a@é.org"} {
		if _, _, err := SplitEmail(bad); err == nil {
			t.Fatalf("SplitEmail(%q) accepted", bad)
		}
	}
}

func TestNewRejectsBadURL(t *testing.T) {
	for _, raw := range []string{"", "http://keys.example", "https://user@keys.example"} {
		if _, err := New(raw, nil); err == nil {
			t.Fatalf("New(%q) accepted", raw)
		}
	}
}
