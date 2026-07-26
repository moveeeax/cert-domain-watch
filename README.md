# cert-domain-watch

Domain and certificate renewal control for agencies managing client portfolios
across multiple registrars.

An agency with forty client sites has forty renewal dates spread across six
registrar accounts, and the one that lapses is always the one nobody owned.
`cdw` reads the registration data and the TLS chain for every domain in a
portfolio and turns them into one structured result per domain — and into a
per-client report the account manager can forward without editing.

**Status: the checker core works and is what this repository contains.**
Multi-tenant storage, scheduled delivery, PDF reports and billing are not built;
see [Not built yet](#not-built-yet).

## What it checks

**Certificates**, per hostname, on the chain exactly as the server presents it:

| Finding | Meaning |
| --- | --- |
| `cert_expired` / `cert_expiring` | past, or inside the 30/14-day ladder |
| `cert_hostname_mismatch` | the certificate does not cover the hostname (wildcards honoured) |
| `cert_self_signed` | the leaf signed itself |
| `cert_incomplete_chain` | the server sent the leaf only, or the chain does not reach a CA |
| `cert_chain_broken` | the presented chain is not contiguous |
| `cert_weak_signature` / `cert_weak_key` | SHA-1/MD5 signature, or an RSA key under 2048 bits |
| `cert_not_yet_valid` | `notBefore` is in the future |

Verification is done by this tool, not by the dialer. A verifying handshake
collapses "missing intermediate", "wrong hostname" and "expired" into one
aborted connection with nothing left to report — which is precisely the
information an agency needs. `tlscheck` therefore collects the chain without
trust-store verification and then applies rules that are stricter than the
dialer's, not laxer; see the doc comment on `Fetcher.Fetch`.

**Registrations**, over RDAP, with no account and no key:

| Finding | Meaning |
| --- | --- |
| `domain_expired` / `domain_expiring` | past, or inside the 60/14-day ladder |
| `domain_expiry_unknown` | the registry publishes no renewal date — stated out loud, never guessed |
| `domain_transfer_lock_off` | the domain can be moved without a lock release |
| `nameserver_drift` | the nameserver set changed since the last run |
| `rdap_unavailable` | no RDAP service for this TLD |

RDAP coverage is uneven, so it was measured rather than assumed. Six of the
eight TLDs that matter to a European/UK/US agency portfolio publish a usable
renewal date; four do not. The probe, its method and what it changed in the
product are in [`docs/rdap-coverage.md`](docs/rdap-coverage.md), and the result
is queryable:

```sh
cdw coverage
```

## Install

Requires Go 1.23 or newer.

```sh
go install github.com/moveeeax/cert-domain-watch/cmd/cdw@latest
```

Or from a clone:

```sh
git clone https://github.com/moveeeax/cert-domain-watch.git
cd cert-domain-watch
go build -o bin/cdw ./cmd/cdw
```

## Usage

### Check some domains

This example runs as written. `badssl.com` publishes deliberately broken
endpoints for exactly this purpose, so the output below is real, not
illustrative:

```sh
cdw check example.com expired.badssl.com self-signed.badssl.com
```

```
WARNING  example.com
         warning   domain_expiring: domain registration expires in 18 day(s), on 2026-08-13
CRITICAL expired.badssl.com
         critical  cert_expired: certificate expired 4122 day(s) ago, on 2015-04-12
         critical  cert_expired [www.expired.badssl.com]: certificate expired 2908 day(s) ago, on 2018-08-08
         critical  cert_hostname_mismatch [www.expired.badssl.com]: certificate is not valid for www.expired.badssl.com (presented: badssl-fallback-unknown-subdomain-or-no-sni)
         warning   cert_incomplete_chain [www.expired.badssl.com]: server sent the leaf only; the intermediate issued by "BadSSL Intermediate Certificate Authority" is missing and some clients will fail to build a path
         info      rdap_unavailable: no RDAP service for this TLD; registration expiry cannot be checked automatically
CRITICAL self-signed.badssl.com
         critical  cert_self_signed: leaf certificate is self-signed and will not be trusted by browsers
         critical  cert_expired [www.self-signed.badssl.com]: certificate expired 2908 day(s) ago, on 2018-08-08
         critical  cert_hostname_mismatch [www.self-signed.badssl.com]: certificate is not valid for www.self-signed.badssl.com (presented: badssl-fallback-unknown-subdomain-or-no-sni)
         warning   cert_incomplete_chain [www.self-signed.badssl.com]: server sent the leaf only; the intermediate issued by "BadSSL Intermediate Certificate Authority" is missing and some clients will fail to build a path
         info      rdap_unavailable: no RDAP service for this TLD; registration expiry cannot be checked automatically

3 domain(s), 11 finding(s)
```

(Dates move as certificates rotate; the shape does not. Exit code here is `2`.)

Each domain is checked at the apex and at `www.` unless explicit hosts are
given. The exit code is `0` when nothing is critical, `2` when something is, and
`1` when the tool itself failed — cron needs to tell a bad portfolio from a
broken run.

### Audit a whole portfolio and produce the client report

```sh
cdw check -file examples/portfolio.csv -format markdown -agency "Northbound Digital"
```

```markdown
# Domain & certificate audit — Northbound Digital

## Summary

- Clients: **2**
- Domains checked: **3**
- Critical findings: **0**
- Warnings: **3**

## Acme Ltd

| Domain | Registrar | Registration expiry | Transfer lock | Certificate | Status |
| --- | --- | --- | --- | --- | --- |
| example.com | RESERVED-Internet Assigned Numbers Authority | 2026-08-13 (18 d) | locked | 2026-08-29 (34 d) | 1 warning |
...
```

The import file is a CSV of `client,domain,hosts,notes`, or just a pasted list
of domains one per line. Column names are matched in any order and any case; see
[`examples/`](examples/). Every domain belongs to exactly one client, and a
duplicate is rejected rather than silently reassigned.

### Structured output

```sh
cdw check -format json example.com
```

One JSON object per domain: registration, per-host TLS chain, TLD coverage row,
and the merged findings sorted worst-first. This is the record shape the
database will hold later, so nothing downstream has to be redesigned.

### Alert deduplication and nameserver drift

A daily cron that emails "expires in 43 days" every morning trains the agency to
ignore it. Pass a state file and only genuinely new alerts are reported:

```sh
cdw check -file portfolio.csv -state ./cdw-state.json
```

Alerts fire once per rung of the **60 / 30 / 14 / 7 / 1** day ladder, not once
per run. Renewing a domain resets its rungs, so the next cycle alerts again.
Nameserver drift fires on any change against the previous snapshot — but never
on the first sighting, and never because one failed RDAP lookup lost the
baseline. Add `-dry-run` to preview alerts without recording them.

The state file contains a customer's portfolio, and is git-ignored.

### Flags

```
cdw check [flags] [domain ...]
  -file      portfolio file: CSV or one domain per line
  -format    text (default), json or markdown
  -agency    agency name for the markdown report header
  -out       write to a file instead of stdout
  -state     state file for alert dedup and nameserver drift
  -dry-run   with -state, report new alerts without recording them
  -no-tls    skip certificate checks
  -no-rdap   skip registration lookups
  -rdap-url  RDAP bootstrap base URL (default https://rdap.org)
  -timeout   overall timeout for the run (default 1m)
```

## Design notes

**Nothing is guessed.** RDAP does not publish a renewal date for every TLD, and
has no auto-renew field at all. Where the data is absent the result says
`unknown` and the report carries a "Coverage notes" section naming the domains
the agency must confirm in the registrar account. A clean-looking report that
silently omits a blind spot is worse than no report.

**Analysis is separated from transport.** `tlscheck.Analyze` is a pure function
over a certificate chain, and `rdap.Parse` a pure function over a response body,
so every rule is tested against generated certificates and recorded fixtures.
The suite needs no network, no registry and no credentials, which is why CI runs
it on every push.

**Codes are a contract.** Finding codes are stable identifiers; the alert dedup
key, the report and the JSON output all derive from them.

## Not built yet

Deliberately absent, because each needs a credential, an account or a paid
service that this repository will not fake:

- Postgres org/client/domain storage and the scheduled daily run. The alert
  state machine itself is built and tested — it currently persists to a JSON
  file whose shape matches the future tables.
- Delivery: Postmark email, Slack webhooks, Telegram, generic webhooks.
- Monthly per-client PDF report with agency branding and a shareable link.
- Cloudflare zone import (needs an API token).
- Billing, plans and domain-count enforcement.

Also out of scope by product decision rather than for lack of credentials:
uptime/HTTP monitoring, any registrar write action including auto-renewal,
CT-log subdomain discovery, DNSSEC, CAA and DMARC/SPF checks.

## Development

```sh
go test ./...                        # offline: fixtures and generated certificates only
go test ./internal/report -update    # refresh the golden report
go vet ./...
```

CI builds, vets, checks formatting and runs the suite with `-race` on every
push.
