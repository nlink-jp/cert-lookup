# cert-lookup Phase 0 measurements

> Done 2026-11-07 with the owner's free keys (SSLMate Small, Validin Community).
> Only the organization's domain, public examples (`example.com`, `google.com`, `cloudflare.com`)
> and nonexistent names were queried; nothing under investigation. Raw responses stay in the
> development machine's scratch area and are not committed (they are large and full of third-party
> certificate names).

Validin spent: 7 queries for the whole development so far, including 2 before the RFP (budget 15).

## SSLMate CT Search API

| observation | result | consequence for the design |
|---|---|---|
| Page size | **100 issuances** | Page caps are reasoned in issuances |
| Next page | **Every page counts as one query** (remaining 95 → 94) | A domain with N issuances costs ceil(N/100) queries, plus one if the end is confirmed with an empty page |
| Empty answer | An empty array also counts. It carries `Retry-After: 3600` and `Cache-Control: max-age=900` | Confirming emptiness spends a query |
| Order | Oldest-discovered first (google.com page 1 spans August to early October, page 2 Oct 5-20) | As in the RFP, a cap loses the newest |
| Size | One google.com page (100 issuances with names) is **540-608 KB** | Large domains do not fit MCP's 128 KB; thinning is mandatory |
| `match_wildcards` | `foo.nlink.jp` returns 0 without it, the `*.nlink.jp` certificates with it | Enabling it for single hosts is right |
| **Public suffixes** | **`com` and `co.jp` both return 200 with an empty array** (no `invalid_value`) | The RFP's "SSLMate refuses it" is wrong. An empty answer must not read as "no issuance" |
| Wrong key | 401 `{"code":"bad_credentials","message":"The provided API key (…_********) is not recognized…"}` — **the message carries the leading part of the key** | Never pass the upstream message through; build our own text from `code` |
| Limit exceeded | The 11th subdomain query got 429 `{"code":"rate_limited",…}` with **`Retry-After: 264` (seconds)**. The allowance refills gradually (not an hourly reset) | `rate_limited` carries the seconds until retry |
| Remaining | `X-Ratelimit-Limit: 100` for single-host, `10` for subdomain queries — each query kind's allowance shows in the header | `cache_status` reports per kind |
| Issuer DN | `C=US, O=Google Trust Services, CN=WE2` (comma-separated) | Formatted differently from Validin → compare components |
| RSA and ECDSA | cloudflare.com: the two certificates with the same period and names come from **different intermediates** (YR1/YE2, WR1/WE1). No two of 12 share period, names and issuer | Merging on a tuple that includes the issuer does not confuse them |
| `Cache-Control` | `max-age=14400` with results (`86400` for google.com), `900` when empty | A 4-hour cache is reasonable; shorter for empty |

## Validin

| observation | result | consequence for the design |
|---|---|---|
| Wrong key | 403 `{"error":"Unauthorized user"}`; **spends no query** | Returned as a configuration error, not `upstream_error` |
| Nonexistent name | 200, `status: "finished"`, 0 records, `limited: false`; **counts as one query** | Empty answers spend quota; a `finished` zero may be cached |
| Wildcards | `zz9q7-cert-lookup.nlink.jp`, covered by `*.nlink.jp`, returns **0 records** | Validin does not return covering wildcard certificates for a single host; `notes` says the history excludes them |
| Serial number | Not in the response (`details` holds only `domains`, `fingerprint`, `fingerprint_sha256`) | Merge rule 3 uses the stand-in tuple (issuer, validity, names) |
| Issuer DN | `cert_issuer: "/C=US/O=Google Trust Services/CN=WR2"` (slash-separated) and `issuer: {C, O, CN}` | Use the `issuer` components and split SSLMate's DN into components to compare |
| **Default window** | google.com with no window → 125 records, first seen **only in 2026-08 and 2026-11** (September and October absent), `limited: false` | Without a window only a recent subset comes back |
| Explicit window | 2025 → 112 records (February to Dec 1, very uneven by month). `lookback=1095` → 85 records (scattered over 2025-02 to 2026-11) | **`limited: false` does not mean complete.** For large domains Validin's history is a sample |
| Small domain | The organization's domain (8 certificates) returned every issuance since 2024-06 with no window (measured before the RFP) | For domains with few issuances — most suspicious domains — it is expected to come back whole within the index's depth |
| `Cache-Control` | `no-store` on certificate responses | Handled as the RFP already says (local cache held within §4(c)) |

## Conclusions (to be applied to the RFP)

1. SSLMate answers public suffixes with an empty array, so **an empty answer says "SSLMate holds no
   unexpired certificate for this name (public suffixes and unindexed names are empty too)" and never
   "no issuance"**
2. Upstream error messages are not shown; our own text is built from `code` (the key's leading part
   appears in them)
3. `rate_limited` carries the `Retry-After` seconds; `cache_status` reports remaining queries per kind
4. Validin's history **never claims completeness**. The window is always sent explicitly as
   `lookback=1095` to aim at the past, and the answer states the range Validin returned (first and
   last observation dates) and that Validin may return only part
5. Validin's single-host history excludes covering wildcard certificates (stated in `notes`)
6. Merge rule 3 cannot use a serial number; it uses the issuer components (C, O, CN), `not_before`,
   `not_after` and the name set

Decisions for the owner:

- Whether to proceed accepting that **Validin's history is only a sample** (months missing for large domains)
- **SSLMate's last page**: walking to the empty page as documented costs every domain one extra query
  (50 single-host domains an hour, 5 with subdomains). Treating a page under 100 as the last halves the
  cost but rests on an undocumented premise
