# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `make package` runs `govulncheck ./...` first (`make vuln`) and stops on a
  finding, so a release cannot be built past one.

## [0.1.0] - 2026-11-07

First release.

### Added

- Project scaffold: the RFP (en/ja) with the Phase 0 measurements, the strict
  config loader (`[sslmate]` / `[validin]` keys, `[cache] dir`,
  `[network] timeout_seconds`, `CERT_LOOKUP_*` overrides) ported from
  vpn-lookup.
- Lookups from the CLI (RFP Phase 1): the ASCII-only domain gate, the SSLMate
  CT Search client (one page per call, allowance headers, our own error
  messages), the Validin certificate-history and usage client
  (`lookback=1095`), the merge of both sources into issuances with a
  per-domain summary (CAs, names outside the domain), the engine (page walk to
  the documented empty page within a cap, pacing under 5 requests a second,
  per-kind allowance stops, the Validin quota check before sending, a
  per-source cache that never stores failures), text and `--json` output, and
  `--clear-cache`.
- The MCP server (RFP Phase 2): `lookup_certs` (validation identical to the
  CLI's, the engine's whole-call refusals with their codes, a 128 KB ceiling
  that drops issuances oldest first across domains and counts them per
  domain), `cache_status` (keys, cache, SSLMate's allowance as last observed,
  Validin's remaining queries) and `get_usage`, with usage.md pinned to the
  tools, arguments, codes and result values by meta-tests.
- A live e2e suite (`make e2e`): about six SSLMate queries and one Validin
  query a run.

### Fixed (before release, from the independent review)

- An SSLMate allowance block no longer outlives its reason: it lasts until
  Retry-After passes, or for the call when there is none (it had lasted the
  MCP server's lifetime). A walk the allowance cut short is degraded and not
  cached; a refused key stops that source for the call; Validin's sample is
  never offered as the latest issuance when SSLMate failed.
