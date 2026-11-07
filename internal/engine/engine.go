// Package engine is the shared core between the CLI and the MCP server: per
// domain, SSLMate is walked page by page (or answered from cache), Validin is
// asked for history when requested, and the two are merged and summarized.
// The engine is the only clock reader and the only sleeper; both are injected.
//
// Answers are cached per source and merged every time, so one source failing
// never serves a stale combined result and never spends the healthy source's
// allowance again. Failures are never cached.
package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/cache"
	"github.com/nlink-jp/cert-lookup/internal/issuance"
	"github.com/nlink-jp/cert-lookup/internal/sslmate"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

// SSLMateClient and ValidinClient are the injected source surfaces.
type SSLMateClient interface {
	Fetch(q sslmate.Query) (*sslmate.Page, error)
}

type ValidinClient interface {
	Certificates(domain string, subdomains bool) (*validin.Answer, error)
	Usage() (*validin.Remaining, error)
}

// Retention (RFP §2 Configuration).
const (
	// SSLMateTTL matches the API's Cache-Control: max-age=14400.
	SSLMateTTL = 4 * time.Hour
	// SSLMateEmptyTTL matches its max-age=900 on an empty answer.
	SSLMateEmptyTTL = 15 * time.Minute
	// ValidinTTL is long because Validin only answers the past, and its
	// allowance is 10 queries a day.
	ValidinTTL = 7 * 24 * time.Hour
)

// Page caps (RFP §2): pages of 100 issuances. One more request than the cap is
// allowed, for the empty page that confirms the end.
const (
	MaxPagesHost       = 5
	MaxPagesSubdomains = 3
)

// SSLMateInterval keeps requests under the free tier's 5 a second.
const SSLMateInterval = 250 * time.Millisecond

// Whole-call error codes (RFP §2), besides the upstream ones.
const (
	CodeHistoryUnavailable = "history_unavailable"
	CodeQuotaExhausted     = "quota_exhausted"
)

// Truncation marker: SSLMate returns oldest first, so a cut loses the newest.
const TruncatedNewestMissing = "newest_missing"

// Source states.
const (
	StateOK           = "ok"
	StateFailed       = "failed"
	StateNotRequested = "not_requested"
)

// Query kinds, which SSLMate meters separately.
const (
	KindHost       = "single_host"
	KindSubdomains = "subdomains"
)

// CallError stops a whole call before anything (more) is sent.
type CallError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *CallError) Error() string { return e.Message }

// Engine answers lookups. A nil Validin means there is no Validin key.
//
// The scopes go into every cache key of their source: the endpoint and a
// fingerprint of the key, so answers from a test server or another key are
// never served once the setting changes.
type Engine struct {
	SSLMate      SSLMateClient
	Validin      ValidinClient
	SSLMateScope string
	ValidinScope string
	Cache        *cache.Store // nil = caching off
	Now          func() time.Time
	Sleep        func(time.Duration)

	lastSSLMate time.Time
	observed    map[string]Observed
	// blocked holds SSLMate query kinds whose allowance is used up: until the
	// time Retry-After named, or — zero time — for the rest of the current call
	// (a zero remainder gives no time). Entries expire; the server process
	// lives for days and must not stay blocked.
	blocked map[string]time.Time
	// refused holds sources whose key was rejected in the current call.
	refused map[string]bool
}

// Options are one call's switches.
type Options struct {
	Subdomains bool
	History    bool
	Refresh    bool
}

// Observed is SSLMate's allowance as last reported, and when.
type Observed struct {
	Limit      int       `json:"limit"`
	Remaining  int       `json:"remaining"`
	ObservedAt time.Time `json:"observed_at"`
}

// SourceState is one source's part in one domain's result.
type SourceState struct {
	State             string `json:"state"`
	Code              string `json:"code,omitempty"`
	Message           string `json:"message,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	FromCache         bool   `json:"from_cache,omitempty"`
}

// Sources holds both states.
type Sources struct {
	SSLMate SourceState `json:"sslmate"`
	Validin SourceState `json:"validin"`
}

// History describes what Validin returned. Sample is always true: Validin may
// return only part of what was issued, even when it says limited is false
// (measured in Phase 0).
type History struct {
	Records      int        `json:"records"`
	ObservedFrom *time.Time `json:"observed_from,omitempty"`
	ObservedTo   *time.Time `json:"observed_to,omitempty"`
	Sample       bool       `json:"sample"`
}

// DomainResult is the answer for one domain.
type DomainResult struct {
	Domain     string              `json:"domain"`
	Subdomains bool                `json:"subdomains"`
	Summary    issuance.Summary    `json:"summary"`
	Issuances  []issuance.Issuance `json:"issuances"`
	Omitted    int                 `json:"omitted,omitempty"`
	Sources    Sources             `json:"sources"`
	History    *History            `json:"history,omitempty"`
	Truncated  string              `json:"truncated,omitempty"`
	Notes      []string            `json:"notes,omitempty"`
	Degraded   bool                `json:"degraded,omitempty"`
}

// Report is the answer for a batch, in input order.
type Report struct {
	Results          []DomainResult     `json:"results"`
	Degraded         int                `json:"degraded_count"`
	ValidinRemaining *validin.Remaining `json:"validin_remaining,omitempty"`
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) sleep(d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(d)
		return
	}
	time.Sleep(d)
}

// Allowances returns SSLMate's allowance per query kind as last reported in
// this process, for cache_status. It is account state seen at ObservedAt, not
// now.
func (e *Engine) Allowances() map[string]Observed {
	out := map[string]Observed{}
	for k, v := range e.observed {
		out[k] = v
	}
	return out
}

func kind(sub bool) string {
	if sub {
		return KindSubdomains
	}
	return KindHost
}

// Lookup answers for domains already validated and canonical (domain.ParseBatch).
func (e *Engine) Lookup(domains []string, o Options) (*Report, error) {
	rep := &Report{}
	e.startCall()
	if o.History {
		if e.Validin == nil {
			return nil, &CallError{Code: CodeHistoryUnavailable, Message: "history was requested but no Validin key is configured (set [validin] api_key or CERT_LOOKUP_VALIDIN_API_KEY)"}
		}
		need := 0
		for _, d := range domains {
			if o.Refresh || !e.cachedValidin(d, o.Subdomains) {
				need++
			}
		}
		if need > 0 {
			rem, err := e.Validin.Usage()
			if err != nil {
				return nil, callErrorFrom(err, "reading Validin's remaining queries failed")
			}
			rep.ValidinRemaining = rem
			if rem.Smaller() < need {
				return nil, &CallError{Code: CodeQuotaExhausted, Message: quotaMessage(rem, need)}
			}
		}
	}
	for _, d := range domains {
		r := e.lookupOne(d, o)
		if r.Degraded {
			rep.Degraded++
		}
		rep.Results = append(rep.Results, r)
	}
	return rep, nil
}

// startCall forgets what only held for the previous call: blocks without a
// Retry-After, blocks whose Retry-After has passed, and refused keys (the
// operator may have fixed the key and the server is still running).
func (e *Engine) startCall() {
	now := e.now()
	for k, until := range e.blocked {
		if until.IsZero() || !now.Before(until) {
			delete(e.blocked, k)
		}
	}
	e.refused = nil
}

func quotaMessage(rem *validin.Remaining, need int) string {
	msg := fmt.Sprintf("Validin has %d queries left today and %d this month; this call needs %d (domains not in the cache). Nothing was sent.", rem.Daily, rem.Monthly, need)
	if rem.Daily < need && !rem.NextDailyReset.IsZero() {
		msg += " The daily count resets at " + rem.NextDailyReset.Format(time.RFC3339) + "."
	} else if !rem.NextMonthlyReset.IsZero() {
		msg += " The monthly count resets at " + rem.NextMonthlyReset.Format(time.RFC3339) + "."
	}
	return msg + " Ask for fewer domains, or drop history."
}

func callErrorFrom(err error, what string) error {
	var ue *upstream.Error
	if errors.As(err, &ue) {
		return &CallError{Code: ue.Code, Message: what + ": " + ue.Error()}
	}
	return &CallError{Code: upstream.CodeUpstream, Message: what + ": " + err.Error()}
}

func (e *Engine) lookupOne(d string, o Options) DomainResult {
	r := DomainResult{Domain: d, Subdomains: o.Subdomains, Issuances: []issuance.Issuance{}}

	w, ss := e.sslmate(d, o)
	r.Sources.SSLMate = ss
	var sIss []sslmate.Issuance
	if w != nil {
		sIss = w.Issuances
		if !w.Complete {
			r.Truncated = TruncatedNewestMissing
		}
	}

	var vRec []validin.Record
	r.Sources.Validin = SourceState{State: StateNotRequested}
	if o.History {
		ans, vs := e.validin(d, o)
		r.Sources.Validin = vs
		if ans != nil {
			vRec = ans.Records
			r.History = history(ans)
		}
	}

	all := issuance.Merge(sIss, vRec, e.now())
	// Without SSLMate's part the newest issuances are exactly what is missing:
	// Validin's sample must not be read as the latest.
	newestMissing := r.Truncated != "" || r.Sources.SSLMate.State == StateFailed
	r.Summary = issuance.Summarize(all, d, newestMissing)
	for i := range all {
		r.Issuances = append(r.Issuances, all[i].Shown())
	}
	// A walk the allowance cut short is partial for a passing reason: degraded,
	// like a failure, so the CLI does not exit 0 on it.
	r.Degraded = r.Sources.SSLMate.State == StateFailed || r.Sources.Validin.State == StateFailed || (w != nil && w.Exhausted)
	r.Notes = notes(r, w, o)
	return r
}

func history(a *validin.Answer) *History {
	h := &History{Records: len(a.Records), Sample: true}
	for _, rec := range a.Records {
		from := rec.FirstSeen
		if !rec.LoggedAt.IsZero() && (from.IsZero() || rec.LoggedAt.Before(from)) {
			from = rec.LoggedAt
		}
		if !from.IsZero() && (h.ObservedFrom == nil || from.Before(*h.ObservedFrom)) {
			t := from
			h.ObservedFrom = &t
		}
		to := rec.LastSeen
		if !to.IsZero() && (h.ObservedTo == nil || to.After(*h.ObservedTo)) {
			t := to
			h.ObservedTo = &t
		}
	}
	return h
}

func notes(r DomainResult, w *walk, o Options) []string {
	var n []string
	if r.Sources.SSLMate.State == StateFailed {
		n = append(n, "SSLMate failed ("+r.Sources.SSLMate.Code+"): currently valid certificates and revocation are missing from this answer, so the latest issuance is not reported.")
	}
	if r.Sources.Validin.State == StateFailed {
		n = append(n, "Validin failed ("+r.Sources.Validin.Code+"): past issuances are missing from this answer.")
	}
	if w != nil && len(w.Issuances) == 0 {
		n = append(n, "SSLMate holds no unexpired certificate for this name. It answers public suffixes and names it does not index the same way, so this is not evidence that none was issued.")
	}
	if r.Truncated != "" {
		msg := fmt.Sprintf("SSLMate returns the oldest issuances first and the walk stopped after %d pages", w.Pages)
		if w.Exhausted {
			msg += " because the query allowance ran out (this partial answer is not cached; ask again once it refills)"
		}
		n = append(n, msg+"; the newest issuances may be missing, so the latest issuance is not reported.")
	}
	if !o.History {
		n = append(n, "History was not requested: only currently valid certificates (SSLMate) are shown. Ask for history to add past issuances from Validin.")
	} else if r.Sources.Validin.State == StateOK {
		n = append(n, "Validin's history is a sample: it may return only part of what was issued, even when it does not say so. An issuance missing here is not evidence that it was never issued.")
		if !o.Subdomains {
			n = append(n, "Validin's history for a single host holds only certificates naming it; wildcard certificates that cover it are not included.")
		}
	}
	return n
}

// walk is SSLMate's answer for one domain, as cached.
type walk struct {
	Issuances []sslmate.Issuance `json:"issuances"`
	// Complete is true only when an empty page confirmed the end.
	Complete  bool `json:"complete"`
	Pages     int  `json:"pages"`
	Exhausted bool `json:"exhausted,omitempty"`
}

func (e *Engine) sslmateKey(d string, sub bool) string {
	return cache.Key("sslmate", e.SSLMateScope, kind(sub), d)
}

func (e *Engine) sslmate(d string, o Options) (*walk, SourceState) {
	key := e.sslmateKey(d, o.Subdomains)
	if !o.Refresh && e.Cache != nil {
		if raw, at, ok := e.Cache.Load(key); ok {
			var w walk
			if json.Unmarshal(raw, &w) == nil {
				ttl := SSLMateTTL
				if len(w.Issuances) == 0 {
					ttl = SSLMateEmptyTTL
				}
				if e.now().Sub(at) <= ttl {
					return &w, SourceState{State: StateOK, FromCache: true}
				}
			}
		}
	}
	k := kind(o.Subdomains)
	if e.refused[sourceSSLMate] {
		return nil, SourceState{State: StateFailed, Code: upstream.CodeInvalidAPIKey, Message: "SSLMate refused the key earlier in this call; not sent (check [sslmate] api_key)"}
	}
	if until, ok := e.blocked[k]; ok {
		st := SourceState{State: StateFailed, Code: upstream.CodeRateLimited, Message: "SSLMate's allowance for this kind of query ran out earlier in this call; not sent"}
		if !until.IsZero() {
			st.Message = "SSLMate's allowance for this kind of query is used up until its Retry-After passes; not sent"
			st.RetryAfterSeconds = int((until.Sub(e.now()) + time.Second - 1) / time.Second)
		}
		return nil, st
	}
	w, err := e.walkSSLMate(d, o.Subdomains)
	if err != nil {
		st := SourceState{State: StateFailed, Code: upstream.CodeUpstream, Message: err.Error()}
		var ue *upstream.Error
		if errors.As(err, &ue) {
			st.Code, st.RetryAfterSeconds = ue.Code, ue.RetryAfter
			switch ue.Code {
			case upstream.CodeRateLimited:
				e.block(k, ue.RetryAfter)
			case upstream.CodeInvalidAPIKey:
				e.refuse(sourceSSLMate)
			}
		}
		return nil, st
	}
	if !w.Exhausted {
		// A walk cut short by the allowance is partial for a passing reason;
		// caching it would serve the cut answer for hours after a refill.
		e.put(key, w)
	}
	return w, SourceState{State: StateOK}
}

const (
	sourceSSLMate = "sslmate"
	sourceValidin = "validin"
)

// block stops a query kind: until Retry-After passes when SSLMate gave one,
// otherwise for the rest of the current call.
func (e *Engine) block(k string, retryAfter int) {
	if e.blocked == nil {
		e.blocked = map[string]time.Time{}
	}
	var until time.Time
	if retryAfter > 0 {
		until = e.now().Add(time.Duration(retryAfter) * time.Second)
	}
	e.blocked[k] = until
}

func (e *Engine) refuse(src string) {
	if e.refused == nil {
		e.refused = map[string]bool{}
	}
	e.refused[src] = true
}

// walkSSLMate follows pages until an empty one (the documented end), the page
// cap, or a zero remaining allowance. The cap counts pages with issuances; one
// more request is allowed to confirm the end, and if that one holds issuances
// they are kept (they were paid for) and the walk is still marked cut — so at
// most (cap+1) pages of 100 come back.
func (e *Engine) walkSSLMate(d string, sub bool) (*walk, error) {
	maxPages := MaxPagesHost
	if sub {
		maxPages = MaxPagesSubdomains
	}
	w := &walk{Issuances: []sslmate.Issuance{}}
	after := ""
	for req := 0; req <= maxPages; req++ {
		e.pace()
		p, err := e.SSLMate.Fetch(sslmate.Query{Domain: d, IncludeSubdomains: sub, After: after})
		if err != nil {
			return nil, err
		}
		e.observe(kind(sub), p.Allowance)
		// Unknown (-1) is not exhausted; zero is. The rest of the call sends no
		// more queries of this kind — also when the page that used the last
		// query was the empty one that completed this walk.
		if p.Allowance.Remaining == 0 {
			e.block(kind(sub), 0)
		}
		if len(p.Issuances) == 0 {
			w.Complete = true
			return w, nil
		}
		w.Pages++
		w.Issuances = append(w.Issuances, p.Issuances...)
		after = p.Issuances[len(p.Issuances)-1].ID
		if p.Allowance.Remaining == 0 {
			w.Exhausted = true
			return w, nil
		}
	}
	return w, nil
}

func (e *Engine) pace() {
	if !e.lastSSLMate.IsZero() {
		if wait := SSLMateInterval - e.now().Sub(e.lastSSLMate); wait > 0 {
			e.sleep(wait)
		}
	}
	e.lastSSLMate = e.now()
}

func (e *Engine) observe(k string, a sslmate.Allowance) {
	if a.Remaining < 0 {
		return
	}
	if e.observed == nil {
		e.observed = map[string]Observed{}
	}
	e.observed[k] = Observed{Limit: a.Limit, Remaining: a.Remaining, ObservedAt: e.now().UTC()}
}

func (e *Engine) validinKey(d string, sub bool) string {
	return cache.Key("validin", e.ValidinScope, kind(sub), d)
}

func (e *Engine) cachedValidin(d string, sub bool) bool {
	if e.Cache == nil {
		return false
	}
	_, ok := e.Cache.Get(e.validinKey(d, sub), e.now(), ValidinTTL)
	return ok
}

func (e *Engine) validin(d string, o Options) (*validin.Answer, SourceState) {
	key := e.validinKey(d, o.Subdomains)
	if !o.Refresh && e.Cache != nil {
		if raw, ok := e.Cache.Get(key, e.now(), ValidinTTL); ok {
			var a validin.Answer
			if json.Unmarshal(raw, &a) == nil {
				return &a, SourceState{State: StateOK, FromCache: true}
			}
		}
	}
	if e.refused[sourceValidin] {
		return nil, SourceState{State: StateFailed, Code: upstream.CodeInvalidAPIKey, Message: "Validin refused the key earlier in this call; not sent (check [validin] api_key)"}
	}
	a, err := e.Validin.Certificates(d, o.Subdomains)
	if err != nil {
		st := SourceState{State: StateFailed, Code: upstream.CodeUpstream, Message: err.Error()}
		var ue *upstream.Error
		if errors.As(err, &ue) {
			st.Code, st.RetryAfterSeconds = ue.Code, ue.RetryAfter
			if ue.Code == upstream.CodeInvalidAPIKey {
				e.refuse(sourceValidin)
			}
		}
		return nil, st
	}
	e.put(key, a)
	return a, SourceState{State: StateOK}
}

func (e *Engine) put(key string, v any) {
	if e.Cache == nil {
		return
	}
	if raw, err := json.Marshal(v); err == nil {
		_ = e.Cache.Put(key, raw, e.now()) // a cache write failure never fails a lookup
	}
}
