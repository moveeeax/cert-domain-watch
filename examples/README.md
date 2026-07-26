# Examples

`portfolio.csv` is a sample import file using IANA reserved example domains, so
it is safe to run against without touching anyone's infrastructure.

Column names are matched case-insensitively and in any order. Accepted aliases:

| Field | Accepted headers |
| --- | --- |
| client | `client`, `client_name`, `customer`, `account` |
| domain | `domain`, `name`, `zone` |
| hosts | `hosts`, `hostnames` — space, `;` or `\|` separated |
| notes | `notes`, `note` |

`hosts` is optional: an empty value means the apex plus `www.`.

A file with no commas is read as a plain list, one domain per line, with `#`
comments — which is what an agency usually pastes into an email first:

```
# Acme Ltd
https://example.com/pricing
www.example.net
```
