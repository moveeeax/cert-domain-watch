package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rdapStub serves a canned RDAP response so the CLI can be exercised end to end
// without touching a real registry.
const rdapStub = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client transfer prohibited"],
  "events": [
    { "eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2099-08-13T04:00:00Z" }
  ],
  "nameservers": [
    { "objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE-DNS.NET" }
  ],
  "entities": [
    {
      "roles": ["registrar"],
      "handle": "9999",
      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]
    }
  ]
}`

// minimalStub is a registry that answers but publishes neither an expiration
// event nor status codes — the case that always produces findings.
const minimalStub = `{
  "objectClassName": "domain",
  "ldhName": "example.de",
  "events": [{ "eventAction": "last changed", "eventDate": "2024-11-02T10:44:15Z" }],
  "nameservers": [{ "objectClassName": "nameserver", "ldhName": "ns1.example-dns.de" }]
}`

func stubServer(t *testing.T) string {
	return stubServerWith(t, rdapStub)
}

func stubServerWith(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRunCheckJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "result.json")
	err := run([]string{
		"check", "-no-tls", "-format", "json",
		"-rdap-url", stubServer(t), "-out", out,
		"example.com",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var results []struct {
		Domain       string `json:"domain"`
		Severity     string `json:"severity"`
		Registration struct {
			Registrar    string `json:"registrar"`
			ExpiryState  string `json:"expiry_state"`
			TransferLock string `json:"transfer_lock"`
		} `json:"registration"`
	}
	if err := json.Unmarshal(b, &results); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, b)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Domain != "example.com" {
		t.Errorf("domain = %q", results[0].Domain)
	}
	if results[0].Registration.ExpiryState != "known" {
		t.Errorf("expiry state = %q, want known", results[0].Registration.ExpiryState)
	}
	if results[0].Registration.TransferLock != "yes" {
		t.Errorf("transfer lock = %q, want yes", results[0].Registration.TransferLock)
	}
	if results[0].Severity != "info" {
		t.Errorf("severity = %q, want info for a healthy domain", results[0].Severity)
	}
}

func TestRunCheckFromCSVAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "portfolio.csv")
	if err := os.WriteFile(csv, []byte("client,domain\nAcme Ltd,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "audit.md")

	err := run([]string{
		"check", "-no-tls", "-format", "markdown", "-agency", "Northbound Digital",
		"-rdap-url", stubServer(t), "-file", csv, "-out", out,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"Northbound Digital", "## Acme Ltd", "example.com", "Example Registrar, Inc."} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
}

// The state file is what stops a daily cron from re-sending yesterday's alert;
// the CLI must honour it across runs.
func TestRunCheckStateSuppressesRepeats(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	url := stubServerWith(t, minimalStub)

	first := filepath.Join(dir, "1.json")
	if err := run([]string{"check", "-no-tls", "-format", "json", "-rdap-url", url,
		"-state", state, "-out", first, "example.de"}); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if countFindings(t, first) == 0 {
		t.Fatal("first run should report the findings for a fresh domain")
	}

	second := filepath.Join(dir, "2.json")
	if err := run([]string{"check", "-no-tls", "-format", "json", "-rdap-url", url,
		"-state", state, "-out", second, "example.de"}); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if n := countFindings(t, second); n != 0 {
		t.Fatalf("second run re-reported %d finding(s); dedup is broken", n)
	}
}

func TestRunCheckDryRunDoesNotRecord(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	url := stubServerWith(t, minimalStub)
	out := filepath.Join(dir, "out.json")

	for i := 0; i < 2; i++ {
		if err := run([]string{"check", "-no-tls", "-format", "json", "-rdap-url", url,
			"-state", state, "-dry-run", "-out", out, "example.de"}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if countFindings(t, out) == 0 {
			t.Fatalf("run %d: a dry run must keep reporting the same alerts", i)
		}
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("a dry run must not write the state file")
	}
}

func TestRunCheckNoTargets(t *testing.T) {
	if err := run([]string{"check", "-no-tls"}); err == nil {
		t.Fatal("expected an error when no domains are given")
	}
}

func TestRunUnknownCommandAndFormat(t *testing.T) {
	if err := run([]string{"nope"}); err == nil {
		t.Fatal("expected an error for an unknown command")
	}
	err := run([]string{"check", "-no-tls", "-no-rdap", "-format", "yaml", "example.com"})
	if err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Fatalf("err = %v, want an unknown-format error", err)
	}
}

// Exit code 2 must mean "the portfolio has a problem", distinct from exit 1
// which means the tool itself failed. Cron depends on the difference.
func TestRunCheckSignalsCriticalFindings(t *testing.T) {
	dir := t.TempDir()
	// A registry speaking RDAP and saying "no such domain" is the emergency
	// case: the client's domain has been dropped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	}))
	defer srv.Close()

	err := run([]string{"check", "-no-tls", "-format", "json", "-rdap-url", srv.URL,
		"-out", filepath.Join(dir, "out.json"), "dropped.example.com"})
	if !errors.Is(err, errFindings) {
		t.Fatalf("err = %v, want errFindings", err)
	}
}

func TestRunCoverage(t *testing.T) {
	if err := run([]string{"coverage"}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if err := run([]string{"coverage", "-json"}); err != nil {
		t.Fatalf("coverage -json: %v", err)
	}
}

func countFindings(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var results []struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(b, &results); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	n := 0
	for _, r := range results {
		n += len(r.Findings)
	}
	return n
}
