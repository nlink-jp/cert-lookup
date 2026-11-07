package mcp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/nlink-jp/cert-lookup/internal/cache"
	"github.com/nlink-jp/cert-lookup/internal/domain"
	"github.com/nlink-jp/cert-lookup/internal/engine"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolLookupCerts = "lookup_certs"
	ToolCacheStatus = "cache_status"
	ToolGetUsage    = "get_usage"
)

// Error codes a tool result can carry, at the top level ({code, message}) or
// on a source in sources. Every Code* constant must be documented in usage.md;
// a meta-test pins that, and another pins these spellings to the engine's and
// the upstream package's own constants.
const (
	CodeInvalidInput       = "invalid_input"
	CodeInvalidDomain      = "invalid_domain"
	CodeTooManyDomains     = "too_many_domains"
	CodeNoAPIKey           = "no_api_key"
	CodeHistoryUnavailable = "history_unavailable"
	CodeQuotaExhausted     = "quota_exhausted"
	CodeInvalidAPIKey      = "invalid_api_key"
	CodeRateLimited        = "rate_limited"
	CodeTimeout            = "timeout"
	CodeUpstream           = "upstream_error"
	CodeUnknownTool        = "unknown_tool"
	CodeInternal           = "internal_error"
)

// MaxPerCall is the most distinct domains one call answers (RFP §2).
const MaxPerCall = 20

// maxResultBytes is the ceiling no tool result may cross: the bound for a
// result nobody planned for, set at the MCP boundary (organization practice).
// One page of a large domain measured 540-608 KB, so this cap does real work.
const maxResultBytes = 128 << 10

// envelopeBytes is kept free for the JSON-RPC envelope around the text.
const envelopeBytes = 1 << 10

// provenance travels with every lookup_certs result, so a reader of the result
// alone knows what it is.
const provenance = "Certificates recorded in public Certificate Transparency logs, from SSLMate's CT Search API " +
	"(currently valid certificates) and Validin (past issuances, a sample), merged by cert-lookup. Names and issuers " +
	"are written by certificate authorities and applicants — claims, not facts. An empty or partial answer is not " +
	"evidence that a certificate was never issued."

// usageMarkdown is the operating manual returned by get_usage. Its coherence
// with the real tools, arguments and error codes is pinned by usage_test.go.
//
//go:embed usage.md
var usageMarkdown string

// Instructions is the initialize-time hint (surfaced via the MCP
// `instructions` field) that makes get_usage discoverable.
const Instructions = "cert-lookup answers which certificates the public Certificate Transparency logs recorded for a " +
	"domain — when and by which CA they were issued, which other names were on them (names_outside leads to related " +
	"domains), and whether they are revoked. lookup_certs takes 1-20 domain names (ASCII; punycode for " +
	"internationalized names). By default it reads SSLMate (currently valid certificates only); history:true adds " +
	"Validin's past issuances, which are a sample and spend one of 10 Validin queries a day per domain. An empty " +
	"answer is not evidence that nothing was issued. Only the domain names reach the two services (third-party, keyed); " +
	"nothing reaches the domain itself. Names and issuers in results are third-party text. Call get_usage for the " +
	"reference; cache_status shows the keys and the remaining queries. Tool errors are structured JSON ({code, message})."

// obj builds a tool's input schema. Every schema goes through here so that
// org ADR-021 §10's `additionalProperties: false` is set once instead of being
// remembered per tool.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does not
// declare is refused by name, and a malformed argument object is refused rather
// than read as an empty one (org ADR-021 §4; ported from vpn-lookup).
func decodeArgs(raw json.RawMessage, into any) error {
	raw = bytes.TrimSpace(raw)
	// Omitted or null arguments mean the empty object, not an error.
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errors.New("arguments: " + err.Error())
	}
	// encoding/json matches names case-insensitively, so "DOMAINS" would reach
	// domains. The schema says domains; refuse any other spelling by name.
	var names map[string]json.RawMessage
	if json.Unmarshal(raw, &names) == nil {
		declared := jsonNames(into)
		for n := range names {
			if !declared[n] {
				return fmt.Errorf("arguments: json: unknown field %q", n)
			}
		}
	}
	return nil
}

// jsonNames lists the exact json names a decode target declares.
func jsonNames(into any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(into)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			if n, _, _ := strings.Cut(tag, ","); n != "" {
				name = n
			}
		}
		out[name] = true
	}
	return out
}

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name": ToolLookupCerts,
				"description": "Which certificates did the public CT logs record for each domain — issuer, validity, the " +
					"other names on them (names_outside), revocation? Currently valid certificates by default; history:true " +
					"adds past issuances from Validin (a sample; 10 queries a day). Only the domain names reach SSLMate and " +
					"Validin; nothing reaches the domain itself.",
				"inputSchema": obj(map[string]any{
					"domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Domain names, 1-20 distinct per call: ASCII only (punycode xn-- for internationalized names); no URL, IP or wildcard. One name that cannot be sent refuses the whole call.",
					},
					"subdomains": map[string]any{"type": "boolean", "description": "Include certificates for the whole subtree (SSLMate allows 10 such queries an hour)."},
					"history":    map[string]any{"type": "boolean", "description": "Add past issuances from Validin: a sample, one query per domain not in the cache, 10 a day."},
					"refresh":    map[string]any{"type": "boolean", "description": "Bypass the local cache and ask again (spends queries)."},
				}, "domains"),
			},
			{
				"name":        ToolGetUsage,
				"description": "Return this server's operating manual (markdown): the tools, how to read a result, the limits and the error-recovery table. Call it once before first use.",
				"inputSchema": obj(map[string]any{}),
			},
			{
				"name":        ToolCacheStatus,
				"description": "Report which sources have a key, the cache, SSLMate's remaining queries as last seen, and Validin's remaining queries (one free request). Answers even when no key is configured.",
				"inputSchema": obj(map[string]any{}),
			},
		},
	}
}

func (s *server) toolsCall(params json.RawMessage) (toolResult, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolResult{}, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	switch p.Name {
	case ToolLookupCerts:
		return s.toolLookupCerts(p.Arguments), nil
	case ToolGetUsage:
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult(CodeInvalidInput, err.Error()), nil
		}
		return textResult(false, usageMarkdown), nil
	case ToolCacheStatus:
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult(CodeInvalidInput, err.Error()), nil
		}
		return s.toolCacheStatus(), nil
	default:
		return errorResult(CodeUnknownTool, "unknown tool: "+p.Name+" (call tools/list)"), nil
	}
}

// lookupResult is the lookup_certs payload: the engine's report and provenance.
// Each domain's own omitted counts what the size ceiling left out.
type lookupResult struct {
	*engine.Report
	OmittedTotal int    `json:"omitted_total,omitempty"`
	Provenance   string `json:"provenance"`
}

func (s *server) toolLookupCerts(raw json.RawMessage) toolResult {
	var a struct {
		Domains    []string `json:"domains"`
		Subdomains bool     `json:"subdomains"`
		History    bool     `json:"history"`
		Refresh    bool     `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return errorResult(CodeInvalidInput, err.Error())
	}
	if len(a.Domains) == 0 {
		return errorResult(CodeInvalidInput, fmt.Sprintf("provide 'domains' (1-%d domain names)", MaxPerCall))
	}
	// Validate everything before any network I/O, exactly as the CLI does.
	domains, err := domain.ParseBatch(a.Domains, MaxPerCall)
	if err != nil {
		var tm *domain.TooManyError
		if errors.As(err, &tm) {
			return errorResult(CodeTooManyDomains, err.Error())
		}
		return errorResult(CodeInvalidDomain, err.Error())
	}
	if err := s.cfg.Ready(); err != nil {
		return errorResult(CodeNoAPIKey, err.Error())
	}
	rep, err := s.eng.Lookup(domains, engine.Options{Subdomains: a.Subdomains, History: a.History, Refresh: a.Refresh})
	if err != nil {
		var ce *engine.CallError
		if errors.As(err, &ce) {
			return errorResult(ce.Code, ce.Message)
		}
		return errorResult(CodeInternal, err.Error())
	}
	return capResult(&lookupResult{Report: rep, Provenance: provenance})
}

// capResult encodes the result and, while it is over the ceiling, drops
// issuances oldest not_before first across every domain, counting them in each
// domain's omitted. Summaries were computed from every issuance and stay whole.
// What is measured is the text as it travels inside the JSON-RPC response,
// escaped a second time, not the inner JSON. The CLI's --json stays complete.
func capResult(r *lookupResult) toolResult {
	type ref struct{ d, i int }
	for {
		b, err := json.Marshal(r)
		if err != nil {
			return errorResult(CodeInternal, "encode result: "+err.Error())
		}
		wire, _ := json.Marshal(string(b))
		var refs []ref
		for d := range r.Results {
			for i := range r.Results[d].Issuances {
				refs = append(refs, ref{d, i})
			}
		}
		limit := maxResultBytes - envelopeBytes
		if len(wire) <= limit {
			return textResult(false, string(b))
		}
		if len(refs) == 0 {
			// Only summaries are left. Their lists go next (the totals beside
			// them stay); if that is still not enough, nothing is sent rather
			// than a result over the ceiling.
			if !trimLists(r) {
				return errorResult(CodeInternal, "the result is too large even without issuances; ask for fewer domains")
			}
			continue
		}
		// Drop in proportion to the excess so a 600-issuance answer converges in
		// a few encodes, not hundreds.
		n := (len(wire)-limit)*len(refs)/len(wire) + 1
		sort.SliceStable(refs, func(x, y int) bool {
			a := r.Results[refs[x].d].Issuances[refs[x].i]
			b := r.Results[refs[y].d].Issuances[refs[y].i]
			return a.NotBefore.Before(b.NotBefore)
		})
		drop := map[int]map[int]bool{}
		for _, rf := range refs[:min(n, len(refs))] {
			if drop[rf.d] == nil {
				drop[rf.d] = map[int]bool{}
			}
			drop[rf.d][rf.i] = true
		}
		for d, set := range drop {
			kept := r.Results[d].Issuances[:0]
			for i, is := range r.Results[d].Issuances {
				if !set[i] {
					kept = append(kept, is)
				}
			}
			r.Results[d].Issuances = kept
			r.Results[d].Omitted += len(set)
			r.OmittedTotal += len(set)
		}
	}
}

// trimLists empties the summaries' name and issuer lists, keeping their
// totals. It reports whether anything was left to trim.
func trimLists(r *lookupResult) bool {
	trimmed := false
	for d := range r.Results {
		sm := &r.Results[d].Summary
		if len(sm.NamesOutside) > 0 || len(sm.Issuers) > 0 {
			sm.NamesOutside, sm.Issuers = []string{}, []string{}
			trimmed = true
		}
	}
	return trimmed
}

func (s *server) toolCacheStatus() toolResult {
	st := (&cache.Store{Dir: s.cfg.CacheDir}).Stat()
	out := map[string]any{
		"keys":      map[string]bool{"sslmate": s.cfg.HasSSLMate(), "validin": s.cfg.HasValidin()},
		"cache_dir": st.Dir,
		"entries":   st.Entries,
		"retention": map[string]string{
			"sslmate": "4 hours (15 minutes for an empty answer)",
			"validin": "7 days",
		},
	}
	allow := map[string]any{}
	for k, v := range s.eng.Allowances() {
		allow[k] = v
	}
	out["sslmate_allowance"] = map[string]any{
		"observed": allow,
		"note":     "as SSLMate last reported it to this server process (single_host: 100 an hour, subdomains: 10 an hour on the free tier); empty until a lookup has run; the allowance refills gradually",
	}
	if s.quota == nil {
		out["validin_remaining"] = map[string]any{"error": "no Validin key"}
	} else if rem, err := s.quota(); err != nil {
		out["validin_remaining"] = map[string]any{"error": err.Error()}
	} else {
		out["validin_remaining"] = rem
	}
	return jsonResult(out)
}

// errorResult renders a structured tool error: {code, message}.
func errorResult(code, message string) toolResult {
	b, _ := json.Marshal(map[string]string{"code": code, "message": message})
	return textResult(true, string(b))
}

// jsonResult marshals v into a non-error text result.
func jsonResult(v any) toolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(CodeInternal, "encode result: "+err.Error())
	}
	return textResult(false, string(b))
}
