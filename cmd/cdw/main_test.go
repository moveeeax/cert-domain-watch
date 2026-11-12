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

// writePortfolio writes a two-client CSV and returns its path.
func writePortfolio(t *testing.T, dir string) string {
	t.Helper()
	csv := filepath.Join(dir, "portfolio.csv")
	body := "client,domain\nAcme Ltd,example.com\nBeta GmbH,beispiel.com\nBeta GmbH,beispiel.net\n"
	if err := os.WriteFile(csv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return csv
}

// Each client's file must stand on its own: forwarding Acme's report must not
// leak a single line about Beta.
func TestRunCheckSplitByClientMarkdown(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "reports")

	err := run([]string{
		"check", "-no-tls", "-format", "markdown", "-agency", "Northbound Digital",
		"-rdap-url", stubServer(t), "-file", writePortfolio(t, dir),
		"-split-by-client", "-out", outDir,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "acme-ltd.md,beta-gmbh.md" {
		t.Fatalf("files = %v, want acme-ltd.md and beta-gmbh.md", names)
	}

	acme := readFile(t, filepath.Join(outDir, "acme-ltd.md"))
	for _, want := range []string{"# Domain & certificate audit — Acme Ltd", "Prepared by Northbound Digital", "example.com", "## Summary"} {
		if !strings.Contains(acme, want) {
			t.Errorf("acme report is missing %q:\n%s", want, acme)
		}
	}
	for _, leak := range []string{"Beta GmbH", "beispiel"} {
		if strings.Contains(acme, leak) {
			t.Errorf("acme report leaks %q:\n%s", leak, acme)
		}
	}
	beta := readFile(t, filepath.Join(outDir, "beta-gmbh.md"))
	if strings.Contains(beta, "Acme") || !strings.Contains(beta, "beispiel.net") {
		t.Errorf("beta report has the wrong domains:\n%s", beta)
	}
}

func TestRunCheckSplitByClientJSON(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "reports")
	err := run([]string{
		"check", "-no-tls", "-format", "json", "-rdap-url", stubServer(t),
		"-file", writePortfolio(t, dir), "-split-by-client", "-out", outDir,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var beta []struct {
		Client string `json:"client"`
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(outDir, "beta-gmbh.json"))), &beta); err != nil {
		t.Fatal(err)
	}
	if len(beta) != 2 || beta[0].Domain != "beispiel.com" || beta[1].Domain != "beispiel.net" {
		t.Fatalf("beta-gmbh.json = %+v, want its two domains in input order", beta)
	}
	for _, r := range beta {
		if r.Client != "Beta GmbH" {
			t.Errorf("beta-gmbh.json contains a result for %q", r.Client)
		}
	}
}

// The exit code covers the whole run even when output is split, so cron still
// sees a critical in any one client.
func TestRunCheckSplitExitCodeCoversWholeRun(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		if strings.HasSuffix(r.URL.Path, "/beispiel.net") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
			return
		}
		_, _ = w.Write([]byte(rdapStub))
	}))
	defer srv.Close()

	err := run([]string{"check", "-no-tls", "-format", "markdown", "-rdap-url", srv.URL,
		"-file", writePortfolio(t, dir), "-split-by-client", "-out", filepath.Join(dir, "reports")})
	if !errors.Is(err, errFindings) {
		t.Fatalf("err = %v, want errFindings", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "reports", "acme-ltd.md")); statErr != nil {
		t.Errorf("reports must still be written when findings are critical: %v", statErr)
	}
}

func TestRunCheckClientFilter(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "acme.md")
	err := run([]string{
		"check", "-no-tls", "-format", "markdown", "-rdap-url", stubServer(t),
		"-file", writePortfolio(t, dir), "-client", "acme ltd", "-out", out,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := readFile(t, out)
	if !strings.Contains(got, "# Domain & certificate audit — Acme Ltd") {
		t.Errorf("a filtered report should be titled with the client's name as written:\n%s", got)
	}
	if strings.Contains(got, "beispiel") {
		t.Errorf("filtered report contains another client's domain:\n%s", got)
	}

	err = run([]string{"check", "-no-tls", "-no-rdap", "-file", writePortfolio(t, dir), "-client", "Nobody"})
	if err == nil || !strings.Contains(err.Error(), "no domains for client") {
		t.Fatalf("err = %v, want a no-such-client error", err)
	}

	// Two clients that differ only in case are distinct in the portfolio; a
	// case-insensitive filter must not quietly merge them into one report.
	mixed := filepath.Join(dir, "mixed.csv")
	if err := os.WriteFile(mixed, []byte("client,domain\nAcme,a.example.com\nACME,b.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"check", "-no-tls", "-no-rdap", "-file", mixed, "-client", "acme"})
	if err == nil || !strings.Contains(err.Error(), "several clients") {
		t.Fatalf("err = %v, want an ambiguous-client error", err)
	}
}

func TestRunCheckFlagValidation(t *testing.T) {
	err := run([]string{"check", "-no-tls", "-no-rdap", "-split-by-client", "example.com"})
	if err == nil || !strings.Contains(err.Error(), "-out") {
		t.Errorf("err = %v, want -split-by-client to require -out", err)
	}
	err = run([]string{"check", "-no-tls", "-no-rdap", "-parallel", "0", "example.com"})
	if err == nil || !strings.Contains(err.Error(), "-parallel") {
		t.Errorf("err = %v, want a -parallel error", err)
	}
}

// Results come back in input order however the workers interleave, so two
// runs over the same portfolio produce the same file.
func TestRunCheckParallelKeepsInputOrder(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}
	args := append([]string{"check", "-no-tls", "-format", "json", "-parallel", "3",
		"-rdap-url", stubServer(t), "-out", out}, domains...)
	if err := run(args); err != nil {
		t.Fatalf("run: %v", err)
	}
	var results []struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &results); err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		if r.Domain != domains[i] {
			t.Fatalf("result %d = %s, want %s", i, r.Domain, domains[i])
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
