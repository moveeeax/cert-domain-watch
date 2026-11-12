// Command cdw checks a portfolio of domains for registration and certificate
// renewal risk and renders the result as JSON or as a client-facing report.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
	"github.com/moveeeax/cert-domain-watch/internal/inventory"
	"github.com/moveeeax/cert-domain-watch/internal/rdap"
	"github.com/moveeeax/cert-domain-watch/internal/report"
	"github.com/moveeeax/cert-domain-watch/internal/tlscheck"
	"github.com/moveeeax/cert-domain-watch/internal/watch"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `cdw — domain and certificate renewal control

Usage:
  cdw check [flags] [domain ...]   check domains and print findings
  cdw coverage [flags]             print the per-TLD RDAP coverage matrix
  cdw version                      print the version

Run "cdw check -h" for the check flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errFindings) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "cdw: "+err.Error())
		os.Exit(1)
	}
}

// errFindings signals "ran fine, but the portfolio has critical findings", so
// cron and CI can tell a broken run from a bad portfolio.
var errFindings = errors.New("critical findings present")

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:])
	case "coverage":
		return runCoverage(args[1:])
	case "version":
		fmt.Println("cdw " + version)
		return nil
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	var (
		file      = fs.String("file", "", "portfolio file: CSV (client,domain,hosts,notes) or one domain per line")
		format    = fs.String("format", "text", "output format: text, json or markdown")
		agency    = fs.String("agency", "", "agency name for the markdown report header")
		out       = fs.String("out", "", "write output to this file instead of stdout; with -split-by-client, a directory")
		client    = fs.String("client", "", "check and report only this client's domains (case-insensitive)")
		split     = fs.Bool("split-by-client", false, "write one report per client into the -out directory, named <client-slug>.<ext>")
		parallel  = fs.Int("parallel", watch.DefaultParallel, "number of domains checked at once")
		statePath = fs.String("state", "", "state file for alert dedup and nameserver drift; only new alerts are reported")
		dryRun    = fs.Bool("dry-run", false, "with -state, report new alerts without recording them")
		skipTLS   = fs.Bool("no-tls", false, "skip certificate checks")
		skipRDAP  = fs.Bool("no-rdap", false, "skip registration lookups")
		rdapBase  = fs.String("rdap-url", rdap.DefaultBaseURL, "RDAP bootstrap base URL")
		timeout   = fs.Duration("timeout", 60*time.Second, "overall timeout for the run")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: cdw check [flags] [domain ...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := extension(*format); err != nil {
		return err
	}
	if *split && *out == "" {
		return errors.New("-split-by-client needs -out set to a directory")
	}
	if *parallel < 1 {
		return errors.New("-parallel must be at least 1")
	}

	targets, err := collectTargets(*file, fs.Args())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no domains given; pass domains as arguments or use -file")
	}
	clientName := ""
	if *client != "" {
		targets, clientName, err = filterClient(targets, *client)
		if err != nil {
			return err
		}
	}

	rdapClient := rdap.NewClient()
	rdapClient.BaseURL = *rdapBase
	checker := &watch.Checker{
		RDAP:     rdapClient,
		TLS:      tlscheck.NewFetcher(),
		SkipTLS:  *skipTLS,
		SkipRDAP: *skipRDAP,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	now := time.Now().UTC()
	var progress func(done, total int)
	if isTerminal(os.Stderr) {
		progress = func(done, total int) {
			fmt.Fprintf(os.Stderr, "\rchecked %d/%d domain(s)", done, total)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}
	results := checker.CheckAll(ctx, targets, now, *parallel, progress)

	if *statePath != "" {
		results, err = applyState(*statePath, results, *dryRun)
		if err != nil {
			return err
		}
	}

	if *split {
		if err := writeSplit(*out, results, *format, *agency, now); err != nil {
			return err
		}
	} else {
		rendered, err := render(results, *format, *agency, clientName, now)
		if err != nil {
			return err
		}
		if *out != "" {
			if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
		} else {
			fmt.Print(rendered)
		}
	}

	for _, r := range results {
		if r.Severity == finding.Critical {
			return errFindings
		}
	}
	return nil
}

// applyState replaces each result's findings with only those that are new since
// the last run, so a daily cron does not re-send yesterday's alert.
func applyState(path string, results []watch.Result, dryRun bool) ([]watch.Result, error) {
	st, err := watch.LoadState(path)
	if err != nil {
		return nil, err
	}
	for i := range results {
		fired := st.Reconcile(results[i])
		results[i].Findings = fired
		results[i].Severity = finding.Worst(fired)
	}
	if dryRun {
		return results, nil
	}
	if err := st.Save(path); err != nil {
		return nil, err
	}
	return results, nil
}

func collectTargets(file string, args []string) ([]watch.Target, error) {
	var targets []watch.Target
	if file != "" {
		loaded, err := inventory.LoadFile(file)
		if err != nil {
			return nil, err
		}
		targets = append(targets, loaded...)
	}
	if len(args) > 0 {
		loaded, err := inventory.Load(strings.NewReader(strings.Join(args, "\n")))
		if err != nil {
			return nil, err
		}
		targets = append(targets, loaded...)
	}
	return targets, nil
}

// filterClient keeps the targets of one client. The match ignores case so a
// cron line does not break on "acme ltd", but it must resolve to exactly one
// client as written in the portfolio: that name heads the report.
func filterClient(targets []watch.Target, want string) ([]watch.Target, string, error) {
	want = strings.TrimSpace(want)
	var (
		kept  []watch.Target
		names []string
	)
	for _, t := range targets {
		if !strings.EqualFold(t.Client, want) {
			continue
		}
		kept = append(kept, t)
		names = appendUnique(names, t.Client)
	}
	switch len(names) {
	case 0:
		return nil, "", fmt.Errorf("no domains for client %q in the portfolio", want)
	case 1:
		return kept, names[0], nil
	default:
		return nil, "", fmt.Errorf("client %q matches several clients (%s); use the exact name",
			want, strings.Join(names, ", "))
	}
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// writeSplit writes one file per client into dir, each rendered on its own so
// it carries only that client's domains, summary and coverage notes.
func writeSplit(dir string, results []watch.Result, format, agency string, now time.Time) error {
	groups, err := report.SplitByClient(results)
	if err != nil {
		return err
	}
	ext, err := extension(format)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, g := range groups {
		rendered, err := render(g.Results, format, agency, g.Client, now)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, g.Slug+ext)
		if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	}
	return nil
}

// extension maps an output format onto the file extension used by
// -split-by-client, and rejects unknown formats before any check runs.
func extension(format string) (string, error) {
	switch format {
	case "json":
		return ".json", nil
	case "markdown", "md":
		return ".md", nil
	case "text", "":
		return ".txt", nil
	default:
		return "", fmt.Errorf("unknown format %q (want text, json or markdown)", format)
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func render(results []watch.Result, format, agency, client string, now time.Time) (string, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "markdown", "md":
		return report.Markdown(results, report.Options{Agency: agency, GeneratedAt: now, Client: client}), nil
	case "text", "":
		return renderText(results), nil
	default:
		return "", fmt.Errorf("unknown format %q (want text, json or markdown)", format)
	}
}

func renderText(results []watch.Result) string {
	var b strings.Builder
	total := 0
	for _, r := range results {
		label := r.Domain
		if r.Client != "" && r.Client != "unassigned" {
			label = r.Client + " / " + r.Domain
		}
		if len(r.Findings) == 0 {
			fmt.Fprintf(&b, "OK       %s\n", label)
			continue
		}
		fmt.Fprintf(&b, "%-8s %s\n", strings.ToUpper(r.Severity.String()), label)
		for _, f := range r.Findings {
			scope := ""
			if f.Scope != "" && f.Scope != r.Domain {
				scope = " [" + f.Scope + "]"
			}
			fmt.Fprintf(&b, "         %-9s %s%s: %s\n", f.Severity, f.Code, scope, f.Message)
			total++
		}
	}
	fmt.Fprintf(&b, "\n%d domain(s), %d finding(s)\n", len(results), total)
	return b.String()
}

func runCoverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the matrix as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rows := rdap.Matrix()
	sort.Slice(rows, func(i, j int) bool { return rows[i].TLD < rows[j].TLD })

	if *asJSON {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("%-8s %-24s %-10s %-9s %s\n", "TLD", "REGISTRY", "EXPECTED", "VERIFIED", "NOTE")
	for _, r := range rows {
		fmt.Printf("%-8s %-24s %-10s %-9t %s\n", "."+r.TLD, r.Registry, r.Expected, r.Verified, r.Note)
	}
	fmt.Println("\n'expected' is a prior, not evidence. Nothing is marked verified until a live " +
		"probe confirms it; unlisted TLDs are always unknown.")
	return nil
}
