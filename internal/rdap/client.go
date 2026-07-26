package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the public IANA-backed RDAP bootstrap redirector. It needs
// no account and no key; it 302s to whichever registry serves the TLD.
const DefaultBaseURL = "https://rdap.org"

// ErrNotFound is returned when the registry reports no such domain.
var ErrNotFound = errors.New("domain not found in rdap")

// ErrNoService is returned when no registry RDAP service exists for the TLD.
var ErrNoService = errors.New("no rdap service for this tld")

// maxBody caps the response we are willing to read from a registry.
const maxBody = 4 << 20

// Client performs RDAP domain lookups.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
	// MinInterval throttles consecutive lookups. Registries rate-limit
	// aggressively and an agency portfolio run is a burst of hundreds.
	MinInterval time.Duration

	mu   sync.Mutex
	last time.Time
}

// NewClient returns a Client pointed at the public bootstrap redirector.
func NewClient() *Client {
	return &Client{
		BaseURL:     DefaultBaseURL,
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		UserAgent:   "cert-domain-watch/0.1 (+https://github.com/moveeeax/cert-domain-watch)",
		MinInterval: 250 * time.Millisecond,
	}
}

// Lookup fetches and parses the RDAP record for one domain.
func (c *Client) Lookup(ctx context.Context, domain string, now time.Time) (*Domain, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if name == "" {
		return nil, errors.New("empty domain")
	}
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}

	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	endpoint := strings.TrimSuffix(base, "/") + "/domain/" + url.PathEscape(name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// A 404 is ambiguous and the two meanings could not be further apart.
		// A registry answering with an RDAP error object really means "no such
		// domain", which for an agency is an emergency. The bootstrap
		// redirector answers a plain HTML 404 when it simply has no entry for
		// the TLD — every .de, .eu and .io domain hits this. Reporting that as
		// a dropped domain would put a false critical on the client report, so
		// the body decides.
		if isRDAPBody(resp.Header.Get("Content-Type"), body) {
			return nil, ErrNotFound
		}
		return nil, ErrNoService
	case resp.StatusCode == http.StatusNotImplemented, resp.StatusCode == http.StatusBadRequest:
		return nil, ErrNoService
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("rdap rate limited by %s", resp.Request.URL.Host)
	case resp.StatusCode >= 300:
		return nil, fmt.Errorf("rdap http %d from %s", resp.StatusCode, resp.Request.URL.Host)
	}

	d, err := Parse(body, now)
	if err != nil {
		return nil, err
	}
	if d.Name == "" {
		d.Name = name
	}
	if resp.Request != nil && resp.Request.URL != nil {
		d.Source = resp.Request.URL.Host
	}
	return d, nil
}

// isRDAPBody reports whether a response came from something speaking RDAP
// rather than from a generic HTTP error page.
func isRDAPBody(contentType string, body []byte) bool {
	if !strings.Contains(contentType, "rdap+json") && !strings.Contains(contentType, "/json") {
		return false
	}
	var probe struct {
		ErrorCode       int    `json:"errorCode"`
		ObjectClassName string `json:"objectClassName"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.ErrorCode != 0 || probe.ObjectClassName != ""
}

func (c *Client) throttle(ctx context.Context) error {
	c.mu.Lock()
	wait := time.Duration(0)
	if c.MinInterval > 0 && !c.last.IsZero() {
		if elapsed := time.Since(c.last); elapsed < c.MinInterval {
			wait = c.MinInterval - elapsed
		}
	}
	c.last = time.Now().Add(wait)
	c.mu.Unlock()

	if wait == 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
