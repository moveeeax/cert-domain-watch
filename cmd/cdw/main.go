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
		out       = fs.String("out", "", "write output to this file instead of stdout")
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

	targets, err := collectTargets(*file, fs.Args())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no domains given; pass domains as arguments or use -file")
	}

	client := rdap.NewClient()
	client.BaseURL = *rdapBase
	checker := &watch.Checker{
		RDAP:     client,
		TLS:      tlscheck.NewFetcher(),
		SkipTLS:  *skipTLS,
		SkipRDAP: *skipRDAP,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	now := time.Now().UTC()
	results := make([]watch.Result, 0, len(targets))
	for _, t := range targets {
		results = append(results, checker.Check(ctx, t, now))
	}

	if *statePath != "" {
		results, err = applyState(*statePath, results, *dryRun)
		if err != nil {
			return err
		}
	}

	rendered, err := render(results, *format, *agency, now)
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

func render(results []watch.Result, format, agency string, now time.Time) (string, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "markdown", "md":
		return report.Markdown(results, report.Options{Agency: agency, GeneratedAt: now}), nil
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
