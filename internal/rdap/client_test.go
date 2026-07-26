package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(h http.Handler) (*Client, func()) {
	srv := httptest.NewServer(h)
	c := NewClient()
	c.BaseURL = srv.URL
	c.MinInterval = 0
	return c, srv.Close
}

func TestLookupSuccess(t *testing.T) {
	var gotPath, gotAccept string
	c, closeSrv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAccept = r.URL.Path, r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(mustFixture(t, "com-full.json"))
	}))
	defer closeSrv()

	d, err := c.Lookup(context.Background(), "EXAMPLE.COM.", refTime)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if gotPath != "/domain/example.com" {
		t.Errorf("request path = %q, want /domain/example.com", gotPath)
	}
	if gotAccept == "" {
		t.Error("client must send an Accept header for application/rdap+json")
	}
	if d.ExpiryState != ExpiryKnown {
		t.Errorf("expiry state = %q", d.ExpiryState)
	}
	if d.Source == "" {
		t.Error("source host should record which server answered")
	}
}

func TestLookupFollowsRedirect(t *testing.T) {
	// The bootstrap redirector 302s to the registry that actually serves the
	// TLD; the client must follow and report the final host as the source.
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(mustFixture(t, "com-full.json"))
	}))
	defer registry.Close()

	c, closeSrv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, registry.URL+r.URL.Path, http.StatusFound)
	}))
	defer closeSrv()

	d, err := c.Lookup(context.Background(), "example.com", refTime)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if d.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", d.Registrar)
	}
}

func TestLookupErrors(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        error
	}{
		{
			// A registry speaking RDAP really means the domain is gone.
			name:        "registry says no such domain",
			status:      http.StatusNotFound,
			contentType: "application/rdap+json",
			body:        `{"errorCode":404,"title":"Not Found"}`,
			want:        ErrNotFound,
		},
		{
			// rdap.org answers a plain HTML 404 for TLDs it has no bootstrap
			// entry for — observed for .de, .eu and .io. Treating that as a
			// dropped domain would fire a false critical on every such domain.
			name:        "bootstrap has no entry for the tld",
			status:      http.StatusNotFound,
			contentType: "text/html",
			body:        "<html><body>404 not found</body></html>",
			want:        ErrNoService,
		},
		{
			name:        "json but not rdap",
			status:      http.StatusNotFound,
			contentType: "application/json",
			body:        `{"message":"nope"}`,
			want:        ErrNoService,
		},
		{name: "not implemented", status: http.StatusNotImplemented, want: ErrNoService},
		{name: "bad request", status: http.StatusBadRequest, want: ErrNoService},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, closeSrv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer closeSrv()

			_, err := c.Lookup(context.Background(), "example.com", refTime)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLookupRateLimited(t *testing.T) {
	c, closeSrv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer closeSrv()

	_, err := c.Lookup(context.Background(), "example.com", refTime)
	if err == nil {
		t.Fatal("expected an error on 429")
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrNoService) {
		t.Fatalf("429 must not be mistaken for a definitive answer: %v", err)
	}
}

func TestLookupRejectsEmptyDomain(t *testing.T) {
	c := NewClient()
	if _, err := c.Lookup(context.Background(), "   ", refTime); err == nil {
		t.Fatal("expected an error for an empty domain")
	}
}

func TestThrottleSpacesRequests(t *testing.T) {
	c, closeSrv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(mustFixture(t, "com-full.json"))
	}))
	defer closeSrv()
	c.MinInterval = 40 * time.Millisecond

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.Lookup(context.Background(), "example.com", refTime); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	// Three lookups means two enforced gaps.
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("three lookups took %v, want at least 80ms of throttling", elapsed)
	}
}

func mustFixture(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, name)
}
