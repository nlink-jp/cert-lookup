# cert-lookup

Which certificates did the public Certificate Transparency logs record for a domain — when,
by which certificate authority, for which other names, and are they still valid or revoked?

cert-lookup layers two CT indexes into one answer:

- **SSLMate CT Search API** — currently valid certificates and their revocation status
  (key required; free Small plan).
- **Validin** — past issuances, with `--history` (free Community account). Validin's history
  is a **sample**: for large domains whole months can be missing, and nothing says so.

Only the domain names you look up reach those two services. Nothing reaches the domain
itself — not even a DNS query. For your organization's own work only.

> Status: in development. The CLI works; the MCP server comes in a later phase.

[日本語版 README](README.ja.md)

## Install

Build from source (Go 1.25+):

```bash
make build   # → dist/cert-lookup
```

## Configure

Copy [config.example.toml](config.example.toml) to `~/.config/cert-lookup/config.toml`,
`chmod 600` it, and set the keys (quoted):

```toml
[sslmate]
api_key = "..."   # required

[validin]
api_key = "..."   # optional; only --history uses it
```

Environment variables override the file: `CERT_LOOKUP_SSLMATE_API_KEY`,
`CERT_LOOKUP_VALIDIN_API_KEY`, `CERT_LOOKUP_SSLMATE_BASE_URL`, `CERT_LOOKUP_VALIDIN_BASE_URL`,
`CERT_LOOKUP_CACHE_DIR`, `CERT_LOOKUP_TIMEOUT_SECONDS`.

## Use

```bash
cert-lookup example.com                    # currently valid certificates (SSLMate)
cert-lookup example.com --history          # plus past issuances (Validin, a sample)
cert-lookup example.com --subdomains       # include the whole subtree
cert-lookup example.com --json             # structured output
cat domains.txt | cert-lookup              # up to 20 domains, one per line
cert-lookup --clear-cache                  # delete every cached answer
```

Flags may come anywhere. Names must be ASCII; pass an internationalized name as punycode
(`xn--...`). URLs, IP addresses and wildcards are refused before anything is sent.

### What you get

Per domain: a summary (how many issuances, earliest and latest, the CAs, and the **names
outside the domain** found on its certificates — leads to related domains), then each
issuance with its validity, issuer, revocation status (`revoked` / `not_revoked` /
`unknown`), the CAA values that authorize its CA, the certificate SHA-256s, and which source
saw it. Compare `caa_domains` with the domain's CAA records using doh-lookup.

### Reading the answer

- **An empty answer is not evidence that nothing was issued.** SSLMate holds only unexpired
  certificates, and answers a public suffix (`co.jp`) or an unindexed name with an empty list.
- **Validin's history is a sample.** An issuance missing from it may still exist.
- For a single host, Validin's history leaves out wildcard certificates that cover it
  (SSLMate's part includes them).
- `truncated: "newest_missing"` — SSLMate returns the oldest issuances first, and a large
  domain hit the page cap; the newest may be missing, so the latest is not reported.

### Limits (free tiers)

| Source | Limit |
|---|---|
| SSLMate | 100 single-host and 10 subdomain queries an hour, 5 a second; every page of 100 counts, the empty page that ends a walk too |
| Validin | 10 queries a day, 50 a month, 250 records per query |

With `--history`, cert-lookup checks Validin's remaining queries first (that check is free)
and refuses the call, sending nothing, when they cannot cover the domains not in the cache.
Answers are cached: SSLMate 4 hours (15 minutes when empty), Validin 7 days.

### Exit codes

`0` every source answered for every domain · `1` a domain or a source failed (the answer is
still printed) · `2` usage error, or a call refused before anything was sent.

## Privacy and terms

- The domains you look up reach SSLMate (which logs request URLs) and, with `--history`,
  Validin. Results stay on your machine — unless you use cert-lookup through an AI assistant,
  whose model provider then sees them too.
- Keys travel only in the `Authorization` header; redirects are refused; no error message
  repeats a URL or an upstream message.
- Validin's terms limit use to your organization's own internal security work (§3(e)) and
  require deleting its output when the agreement ends (§4(c)) — `cert-lookup --clear-cache`.

## Documentation

- [RFP](docs/en/cert-lookup-rfp.md) · [Phase 0 measurements](docs/en/cert-lookup-phase0.md)
- [AGENTS.md](AGENTS.md) for contributors

## License

MIT — see [LICENSE](LICENSE).
