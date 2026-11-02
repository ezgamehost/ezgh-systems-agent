package creds

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type fakeNow struct{ t time.Time }

func (f *fakeNow) Now() time.Time { return f.t }

func TestMetadataCredentials(t *testing.T) {
	var tokens, fetches atomic.Int32
	var noBot, refuseToken atomic.Bool
	key := atomic.Value{}
	key.Store("ezgh_one")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("EZGH-Metadata") != "true" {
			t.Errorf("missing EZGH-Metadata header")
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/ezgh/v1/token":
			if r.Header.Get("EZGH-Metadata-Token-TTL-Seconds") == "" {
				t.Errorf("token request without a TTL")
			}
			tokens.Add(1)
			_, _ = io.WriteString(w, "tok\n")
		case r.Method == http.MethodGet && r.URL.Path == "/ezgh/v1/credentials":
			fetches.Add(1)
			if refuseToken.Swap(false) || r.Header.Get("EZGH-Metadata-Token") != "tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if noBot.Load() {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":{"code":"no_bot"}}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiKey": key.Load(), "expiresAt": t0.Add(time.Hour), "bot": "bot_x"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	now := &fakeNow{t0}
	m := &Metadata{Endpoint: srv.URL, Now: now.Now}
	ctx := context.Background()

	if k, err := m.Key(ctx); err != nil || k != "ezgh_one" {
		t.Fatalf("Key = %q, %v", k, err)
	}
	if k, _ := m.Key(ctx); k != "ezgh_one" || fetches.Load() != 1 {
		t.Fatalf("the key wasn't kept: %d fetches", fetches.Load())
	}

	// Refreshed 5 minutes before it expires.
	key.Store("ezgh_two")
	now.t = t0.Add(56 * time.Minute)
	if k, _ := m.Key(ctx); k != "ezgh_two" {
		t.Fatalf("not refreshed before expiry: %q", k)
	}

	// An API refused the key: refetch.
	key.Store("ezgh_three")
	m.Invalidate("ezgh_two")
	if k, _ := m.Key(ctx); k != "ezgh_three" {
		t.Fatalf("not refetched after a 401: %q", k)
	}

	// The metadata token is gone: one new token, then the key.
	refuseToken.Store(true)
	m.Invalidate("ezgh_three")
	before := tokens.Load()
	if _, err := m.Key(ctx); err != nil || tokens.Load() != before+1 {
		t.Fatalf("token not renewed after a 401: %v, %d tokens", err, tokens.Load())
	}

	// No Bot attached: wait, and ask again every 3 minutes.
	noBot.Store(true)
	m.Invalidate("ezgh_three")
	if _, err := m.Key(ctx); !errors.Is(err, ErrNoBot) {
		t.Fatalf("err = %v, want ErrNoBot", err)
	}
	n := fetches.Load()
	now.t = now.t.Add(2 * time.Minute)
	if _, err := m.Key(ctx); !errors.Is(err, ErrNoBot) || fetches.Load() != n {
		t.Fatalf("asked again too soon: %v, %d fetches", err, fetches.Load()-n)
	}
	if NoBotRetry != 3*time.Minute {
		t.Fatalf("NoBotRetry = %s", NoBotRetry)
	}
	now.t = now.t.Add(time.Minute)
	noBot.Store(false)
	if k, err := m.Key(ctx); err != nil || k != "ezgh_three" {
		t.Fatalf("after the Bot was attached: %q, %v", k, err)
	}
}

func TestFileCredentials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(p, []byte("ezgh_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &File{Path: p}
	if k, err := f.Key(context.Background()); err != nil || k != "ezgh_abc" {
		t.Fatalf("Key = %q, %v", k, err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Key(context.Background()); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("a group-readable key file was used: %v", err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Key(context.Background()); err == nil {
		t.Fatal("an empty key file was used")
	}
}

func TestOIDCExchange(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("id-token-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/organizations/org_a/bots/bot_b/oidc-api-keys" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("the exchange sent a credential: %q", r.Header.Get("Authorization"))
		}
		var body struct{ Token string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		n := calls.Add(1)
		if body.Token != "id-token-1" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"unauthenticated"}}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiKey": map[string]any{"expiresAt": t0.Add(time.Hour).Format(time.RFC3339)},
			"token":  "ezgh_k" + string(rune('0'+n)),
		})
	}))
	defer srv.Close()
	now := &fakeNow{t0}
	o := &OIDC{OrgsURL: srv.URL, Organization: "org_a", Bot: "bot_b", TokenFile: tokenFile, Now: now.Now}
	ctx := context.Background()
	if k, err := o.Key(ctx); err != nil || k != "ezgh_k1" {
		t.Fatalf("Key = %q, %v", k, err)
	}
	if k, _ := o.Key(ctx); k != "ezgh_k1" || calls.Load() != 1 {
		t.Fatal("the key wasn't kept")
	}
	now.t = t0.Add(56 * time.Minute)
	if k, _ := o.Key(ctx); k != "ezgh_k2" {
		t.Fatalf("not exchanged again before expiry: %q", k)
	}
	o.Invalidate("ezgh_k2")
	if k, _ := o.Key(ctx); k != "ezgh_k3" {
		t.Fatalf("not exchanged again after a 401: %q", k)
	}
	o.Invalidate("ezgh_k3")
	if err := os.WriteFile(tokenFile, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Key(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a refused token: %v", err)
	}
}

// Metadata requests share one client: connections are reused, not one per request.
func TestMetadataReusesConnections(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	for range 5 {
		p := &Metadata{Endpoint: srv.URL} // a fresh source each time: the client is shared
		if status, _, err := p.do(context.Background(), http.MethodGet, "/", nil); err != nil || status != http.StatusOK {
			t.Fatalf("%d, %v", status, err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections for 5 requests", n)
	}
}

// An IPv6-only guest has no route to the IPv4 address.
func TestMetadataFallsBackWhenTheFirstAddressIsUnreachable(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{"id":"ins_abcdefghijkl","project":"prj_abcdefghijkl","projectId":"01a0eb5f-2a53-74a7-a704-c7efc80b17cf"}`)
	}))
	defer srv.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	unreachable := dead.URL
	dead.Close()

	m := &Metadata{Endpoint: unreachable, Fallback: srv.URL}
	if _, err := m.Project(context.Background()); err != nil || hits.Load() != 1 {
		t.Fatalf("err = %v, fallback hits = %d", err, hits.Load())
	}
}

// An answer is an answer: only an unreachable address moves on to the next.
func TestMetadataKeepsARefusalFromTheFirstAddress(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fallback used after the first address answered")
	}))
	defer second.Close()

	m := &Metadata{Endpoint: first.URL, Fallback: second.URL}
	if _, err := m.Project(context.Background()); err == nil {
		t.Fatal("a 503 was accepted")
	}
}

func TestMetadataDefaultGetsTheIPv6Fallback(t *testing.T) {
	for _, endpoint := range []string{"", "http://169.254.169.254"} {
		first, fallback := (&Metadata{Endpoint: endpoint}).endpoints()
		if first != "http://169.254.169.254" || fallback != "http://[fd65:7a67:6800::254]" {
			t.Fatalf("Endpoint %q: %q then %q", endpoint, first, fallback)
		}
	}
	if _, fallback := (&Metadata{Endpoint: "http://metadata.example"}).endpoints(); fallback != "" {
		t.Fatalf("a custom endpoint got fallback %q", fallback)
	}
}
