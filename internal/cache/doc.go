// Package cache is a JSON-file cache with atomic writes, shared by the CLI and
// the MCP server (ported from vpn-lookup, which took it from shodan-lookup).
//
// Entries are per source: an SSLMate answer and a Validin answer about the same
// domain are separate entries, so one source's outage never makes the healthy
// one's answers expire or be re-fetched. Freshness is judged at read time (the
// fetch time is stored, not an expiry), so a retention change applies to
// entries already on disk.
//
// Never cached: a failed answer. Entry names are hashes of what determined the
// answer (Key), so investigated domains do not sit readable in a directory
// listing. --clear-cache removes everything (Validin terms §4(c) require
// deleting output and copies when the agreement ends).
package cache
