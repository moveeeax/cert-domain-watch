# Domain & certificate audit — Northbound Digital

Generated 2026-03-01 12:00 UTC by cert-domain-watch.

## Summary

- Clients: **2**
- Domains checked: **3**
- Critical findings: **2**
- Warnings: **2**
- Informational: **0**

## Acme Ltd

| Domain | Registrar | Registration expiry | Transfer lock | Certificate | Status |
| --- | --- | --- | --- | --- | --- |
| example.com | Example Registrar, Inc. | 2026-03-12 (10 d) | **off** | 2026-02-25 (-4 d) | 2 critical, 1 warning |

### example.com

- **CRITICAL** `cert_expired` (`www.example.com`) — certificate expired 4 day(s) ago, on 2026-02-25
- **CRITICAL** `domain_expiring` — domain registration expires in 10 day(s), on 2026-03-12
- **WARNING** `domain_transfer_lock_off` — transfer lock is off; the domain can be moved to another registrar without a lock release

## Beta GmbH

| Domain | Registrar | Registration expiry | Transfer lock | Certificate | Status |
| --- | --- | --- | --- | --- | --- |
| beispiel.de | unknown | not published | unknown | not checked | 1 warning |
| beispiel.com | Placeholder Registrar Ltd | 2027-01-04 (309 d) | locked | not checked | OK |

### beispiel.de

- **WARNING** `domain_expiry_unknown` — registry publishes no expiration date over RDAP — renewal must be confirmed in the registrar account

## Coverage notes

Renewal dates below could not be confirmed automatically and must be checked in the registrar account.

- `.de` — DENIC: not served through the rdap.org bootstrap; renewal dates are not automatable today

