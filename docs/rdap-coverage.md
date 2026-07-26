# RDAP coverage probe — 2026-07-26

The product promise is a renewal date an agency can act on. RDAP does not
provide one everywhere, so before building anything around it the eight TLDs
that a European/UK/US agency portfolio actually contains were probed against
live registries.

## Method

Each lookup went through the public IANA-backed bootstrap redirector
`https://rdap.org/domain/<name>`, following redirects to whichever registry
serves the TLD. No account, no key, no paid service. One real registered domain
per TLD was used; the result recorded is what the registry actually returned.

```
cdw check -no-tls -format json <domain>
```

## Results

| TLD | Probe domain | Answered by | Expiration event | Verdict |
| --- | --- | --- | --- | --- |
| `.com` | example.com | rdap.verisign.com | yes — 2026-08-13 | automatable |
| `.net` | example.net | rdap.verisign.com | yes — 2026-08-30 | automatable |
| `.org` | example.org | rdap.publicinterestregistry.org | yes — 2026-08-30 | automatable |
| `.co.uk` | bbc.co.uk | rdap.nominet.uk | yes — 2034-12-13 | automatable |
| `.fr` | afnic.fr | rdap.nic.fr | yes — 2029-07-18 | automatable |
| `.ai` | whois.ai | rdap.identitydigital.services | yes — 2099-01-01 | automatable |
| `.nl` | sidn.nl | rdap.sidn.nl | **no** | answered, but no renewal date published |
| `.de` | denic.de | — | — | **not served through the bootstrap** |
| `.eu` | eurid.eu | — | — | **not served through the bootstrap** |
| `.io` | keycdn.io | — | — | **not served through the bootstrap** |

## What this changes in the product

**Six of the eight target TLDs give a real renewal date.** That is enough for
the core promise to hold for most of a typical portfolio.

**Four do not, and they must be visible in the deliverable.** `.nl` answers but
withholds the date; `.de`, `.eu` and `.io` are not reachable through the
bootstrap at all. Those domains get an explicit `domain_expiry_unknown` finding
and a "Coverage notes" section in every report telling the agency to confirm the
date in the registrar account. A clean-looking report that quietly omits a `.de`
domain would be worse than no report.

**A 404 is not evidence that a domain was dropped.** The bootstrap answers a
plain HTML `404` with `Content-Type: text/html` when it has no entry for a TLD —
that is what `.de`, `.eu` and `.io` return. A registry that genuinely does not
know a domain answers `application/rdap+json` with an RDAP error object. Before
this probe the client treated both the same and would have raised a critical
"this domain has been dropped" alert on every `.de`, `.eu` and `.io` domain in a
customer's portfolio. `rdap.Lookup` now inspects the body and returns
`ErrNoService` (informational: a coverage gap) rather than `ErrNotFound`
(critical: an emergency).

## Caveats

- `.uk` was not probed directly; the matrix infers it from `.co.uk` on the same
  registry and is marked unverified.
- "Not served through the bootstrap" is a statement about the public redirector
  on this date, not proof that no registry endpoint exists. A direct per-TLD
  endpoint may still be reachable; that is a follow-up, not an assumption.
- Registries change what they publish. Every verified row carries the probe date
  so a stale matrix is visible rather than merely old.

## Re-running the probe

```sh
for d in example.com example.net example.org bbc.co.uk afnic.fr sidn.nl \
         denic.de eurid.eu keycdn.io whois.ai; do
  printf '%-16s' "$d"
  cdw check -no-tls -format json "$d" | \
    jq -r '.[0] | (.registration.expiry_state // "no answer") + " " + (.registration.source // "")'
done
```
