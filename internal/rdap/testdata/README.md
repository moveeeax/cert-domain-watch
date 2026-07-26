# RDAP fixtures

Synthetic RDAP responses shaped to RFC 9083, trimmed to the fields this package
reads. They use IANA reserved example domains and placeholder registrar names —
no captured customer data, no real registrant details.

Each fixture is a case the parser must survive:

| File | Case |
| --- | --- |
| `com-full.json` | thick registry: expiration event, status codes, registrar entity, nameservers |
| `de-minimal.json` | registry that answers but publishes no expiration and no status codes |
| `no-lock.json` | domain with status codes present but no transfer prohibition |
| `expired.json` | expiration date already in the past |
| `error-404.json` | RDAP error object rather than a domain object |
