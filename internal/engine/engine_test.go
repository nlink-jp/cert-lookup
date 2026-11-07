package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/cache"
	"github.com/nlink-jp/cert-lookup/internal/sslmate"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

// clock is a fake time source; sleeping advances it.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Sleep(d time.Duration)   { c.t = c.t.Add(d) }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// fakeSSLMate serves n issuances per domain in pages of 100, oldest first.
type fakeSSLMate struct {
	count     map[string]int // domain -> issuances
	remaining int            // allowance after each request; -1 = no header
	fail      map[string]error
	queries   []sslmate.Query
	clk       *clock
	times     []time.Time
}

func (f *fakeSSLMate) Fetch(q sslmate.Query) (*sslmate.Page, error) {
	f.queries = append(f.queries, q)
	if f.clk != nil {
		f.times = append(f.times, f.clk.Now())
	}
	if err := f.fail[q.Domain]; err != nil {
		return nil, err
	}
	start := 0
	if q.After != "" {
		_, _ = fmt.Sscanf(q.After, "id-%d", &start)
		start++
	}
	var is []sslmate.Issuance
	for i := start; i < f.count[q.Domain] && len(is) < sslmate.PageSize; i++ {
		is = append(is, sslmate.Issuance{
			ID: fmt.Sprintf("id-%d", i), TBSSHA256: fmt.Sprintf("%064d", i),
			DNSNames:  []string{q.Domain},
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour),
			NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		})
	}
	rem := f.remaining
	if rem > 0 {
		f.remaining--
	}
	return &sslmate.Page{Issuances: is, Allowance: sslmate.Allowance{Limit: 100, Remaining: rem}}, nil
}

type fakeValidin struct {
	records   map[string][]validin.Record
	fail      error
	remaining validin.Remaining
	usageErr  error
	calls     []string
	usage     int
}

func (f *fakeValidin) Certificates(d string, sub bool) (*validin.Answer, error) {
	f.calls = append(f.calls, d)
	if f.fail != nil {
		return nil, f.fail
	}
	return &validin.Answer{Records: append([]validin.Record{}, f.records[d]...)}, nil
}

func (f *fakeValidin) Usage() (*validin.Remaining, error) {
	f.usage++
	if f.usageErr != nil {
		return nil, f.usageErr
	}
	r := f.remaining
	return &r, nil
}

func newEngine(t *testing.T, s *fakeSSLMate, v *fakeValidin) (*Engine, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)}
	s.clk = clk
	e := &Engine{SSLMate: s, SSLMateScope: "s", ValidinScope: "v", Cache: &cache.Store{Dir: t.TempDir()}, Now: clk.Now, Sleep: clk.Sleep}
	if v != nil {
		e.Validin = v
	}
	return e, clk
}

func TestWalkFollowsPagesToTheEmptyOne(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"example.com": 230}, remaining: -1}
	e, _ := newEngine(t, s, nil)
	rep, err := e.Lookup([]string{"example.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if len(s.queries) != 4 || s.queries[1].After != "id-99" || s.queries[3].After != "id-229" {
		t.Fatalf("queries = %+v; want 3 data pages and the confirming empty page", s.queries)
	}
	if r.Truncated != "" || r.Summary.Issuances != 230 || r.Summary.LatestNotBefore == nil || r.Degraded {
		t.Fatalf("result = %+v", r.Summary)
	}
	if r.Sources.SSLMate.State != StateOK || r.Sources.Validin.State != StateNotRequested {
		t.Fatalf("sources = %+v", r.Sources)
	}
}

func TestPageCapLosesTheNewestAndSaysSo(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"big.example": 1000}, remaining: -1}
	e, _ := newEngine(t, s, nil)
	rep, _ := e.Lookup([]string{"big.example"}, Options{})
	r := rep.Results[0]
	if len(s.queries) != MaxPagesHost+1 {
		t.Fatalf("%d requests; want the cap plus one", len(s.queries))
	}
	if r.Truncated != TruncatedNewestMissing || r.Summary.LatestNotBefore != nil || r.Summary.Issuances != 600 {
		t.Fatalf("truncated=%q latest=%v n=%d", r.Truncated, r.Summary.LatestNotBefore, r.Summary.Issuances)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "newest issuances may be missing") {
		t.Fatalf("notes = %v", r.Notes)
	}

	s2 := &fakeSSLMate{count: map[string]int{"big.example": 1000}, remaining: -1}
	e2, _ := newEngine(t, s2, nil)
	_, _ = e2.Lookup([]string{"big.example"}, Options{Subdomains: true})
	if len(s2.queries) != MaxPagesSubdomains+1 {
		t.Fatalf("%d subdomain requests; want %d", len(s2.queries), MaxPagesSubdomains+1)
	}
}

// Remaining 0 stops the walk short and keeps the rest of the call from
// sending that kind of query.
func TestZeroAllowanceStopsTheCall(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"a.example": 250, "b.example": 1}, remaining: 1}
	e, _ := newEngine(t, s, nil)
	rep, _ := e.Lookup([]string{"a.example", "b.example"}, Options{})
	if len(s.queries) != 2 {
		t.Fatalf("queries = %d; want 2 (stop at zero, send nothing for b)", len(s.queries))
	}
	a, b := rep.Results[0], rep.Results[1]
	if a.Truncated != TruncatedNewestMissing || !strings.Contains(strings.Join(a.Notes, " "), "allowance ran out") {
		t.Fatalf("a = %q %v", a.Truncated, a.Notes)
	}
	if b.Sources.SSLMate.Code != upstream.CodeRateLimited || !b.Degraded || rep.Degraded != 1 {
		t.Fatalf("b = %+v, degraded %d", b.Sources.SSLMate, rep.Degraded)
	}
	if obs := e.Allowances()[KindHost]; obs.Remaining != 0 || obs.ObservedAt.IsZero() {
		t.Fatalf("observed = %+v", obs)
	}
}

func TestRateLimitedStopsOnlyThatKind(t *testing.T) {
	rl := &upstream.Error{Source: "SSLMate", Code: upstream.CodeRateLimited, Status: 429, RetryAfter: 264, Detail: "used up"}
	s := &fakeSSLMate{count: map[string]int{"b.example": 1}, remaining: -1, fail: map[string]error{"a.example": rl}}
	e, _ := newEngine(t, s, nil)
	rep, _ := e.Lookup([]string{"a.example", "b.example"}, Options{Subdomains: true})
	if len(s.queries) != 1 {
		t.Fatalf("queries = %d; b must not be sent after a 429 of the same kind", len(s.queries))
	}
	for _, r := range rep.Results {
		if r.Sources.SSLMate.Code != upstream.CodeRateLimited || r.Sources.SSLMate.RetryAfterSeconds != 264 {
			t.Fatalf("%s: %+v", r.Domain, r.Sources.SSLMate)
		}
	}
	rep, _ = e.Lookup([]string{"b.example"}, Options{})
	if rep.Results[0].Sources.SSLMate.State != StateOK {
		t.Fatalf("single-host queries are metered apart: %+v", rep.Results[0].Sources.SSLMate)
	}
}

func TestCacheAndItsLimits(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"full.example": 3}, remaining: -1}
	e, clk := newEngine(t, s, nil)
	_, _ = e.Lookup([]string{"full.example", "empty.example"}, Options{})
	n := len(s.queries)
	rep, _ := e.Lookup([]string{"full.example", "empty.example"}, Options{})
	if len(s.queries) != n || !rep.Results[0].Sources.SSLMate.FromCache {
		t.Fatal("a repeat within the TTL must come from the cache")
	}
	clk.Advance(SSLMateEmptyTTL + time.Second)
	_, _ = e.Lookup([]string{"full.example", "empty.example"}, Options{})
	if len(s.queries) != n+1 || s.queries[n].Domain != "empty.example" {
		t.Fatalf("after 15 minutes only the empty answer is re-asked: %+v", s.queries[n:])
	}
	_, _ = e.Lookup([]string{"full.example"}, Options{Refresh: true})
	if s.queries[len(s.queries)-1].Domain != "full.example" {
		t.Fatal("refresh must bypass the cache")
	}
}

func TestFailuresAreNotCached(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{}, remaining: -1, fail: map[string]error{"x.example": errors.New("boom")}}
	e, _ := newEngine(t, s, nil)
	_, _ = e.Lookup([]string{"x.example"}, Options{})
	delete(s.fail, "x.example")
	rep, _ := e.Lookup([]string{"x.example"}, Options{})
	if rep.Results[0].Sources.SSLMate.State != StateOK || rep.Results[0].Sources.SSLMate.FromCache {
		t.Fatalf("a failure was served from the cache: %+v", rep.Results[0].Sources.SSLMate)
	}
}

func TestEmptyAnswerIsNotNoIssuance(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{}, remaining: -1}
	e, _ := newEngine(t, s, nil)
	rep, _ := e.Lookup([]string{"co.jp"}, Options{})
	got := strings.Join(rep.Results[0].Notes, " ")
	if !strings.Contains(got, "not evidence that none was issued") || rep.Results[0].Degraded {
		t.Fatalf("notes = %v", rep.Results[0].Notes)
	}
}

func TestHistoryWithoutValidinKey(t *testing.T) {
	s := &fakeSSLMate{remaining: -1}
	e, _ := newEngine(t, s, nil)
	_, err := e.Lookup([]string{"example.com"}, Options{History: true})
	var ce *CallError
	if !errors.As(err, &ce) || ce.Code != CodeHistoryUnavailable || len(s.queries) != 0 {
		t.Fatalf("err = %v, queries %d", err, len(s.queries))
	}
}

func TestQuotaCheckBeforeSending(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{}, remaining: -1}
	v := &fakeValidin{remaining: validin.Remaining{Daily: 9, Monthly: 1}}
	e, _ := newEngine(t, s, v)
	_, err := e.Lookup([]string{"a.example", "b.example"}, Options{History: true})
	var ce *CallError
	if !errors.As(err, &ce) || ce.Code != CodeQuotaExhausted || len(v.calls) != 0 || len(s.queries) != 0 {
		t.Fatalf("err = %v; validin calls %d, sslmate %d — the smaller (monthly) remainder binds and nothing is sent", err, len(v.calls), len(s.queries))
	}
	if !strings.Contains(ce.Message, "1 this month") || !strings.Contains(ce.Message, "needs 2") {
		t.Fatalf("message = %s", ce.Message)
	}

	// One domain fits; once cached it no longer counts, unless refreshed.
	rep, err := e.Lookup([]string{"a.example"}, Options{History: true})
	if err != nil || rep.Results[0].Sources.Validin.State != StateOK || rep.ValidinRemaining == nil {
		t.Fatalf("err=%v rep=%+v", err, rep)
	}
	v.remaining = validin.Remaining{Daily: 0, Monthly: 0}
	usage := v.usage
	if _, err := e.Lookup([]string{"a.example"}, Options{History: true}); err != nil || v.usage != usage {
		t.Fatalf("a cached domain needs no query and no usage check: err=%v", err)
	}
	if _, err := e.Lookup([]string{"a.example"}, Options{History: true, Refresh: true}); !errors.As(err, &ce) || ce.Code != CodeQuotaExhausted {
		t.Fatalf("refresh counts every domain: err=%v", err)
	}
}

func TestUsageFailureStopsTheCall(t *testing.T) {
	s := &fakeSSLMate{remaining: -1}
	v := &fakeValidin{usageErr: &upstream.Error{Source: "Validin", Code: upstream.CodeInvalidAPIKey, Status: 403, Detail: "the API key was not accepted"}}
	e, _ := newEngine(t, s, v)
	_, err := e.Lookup([]string{"example.com"}, Options{History: true})
	var ce *CallError
	if !errors.As(err, &ce) || ce.Code != upstream.CodeInvalidAPIKey || len(s.queries) != 0 {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryMergesAndNotesTheSample(t *testing.T) {
	old := validin.Record{CommonName: "example.com", Issuer: validin.Issuer{O: "Old CA"}, NotBefore: time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2025, 7, 20, 0, 0, 0, 0, time.UTC), FingerprintSHA256: strings.Repeat("e", 64), FirstSeen: time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 6, 21, 0, 0, 0, 0, time.UTC)}
	s := &fakeSSLMate{count: map[string]int{"example.com": 1}, remaining: -1}
	v := &fakeValidin{records: map[string][]validin.Record{"example.com": {old}}, remaining: validin.Remaining{Daily: 10, Monthly: 50}}
	e, _ := newEngine(t, s, v)
	rep, err := e.Lookup([]string{"example.com"}, Options{History: true})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Summary.Issuances != 2 || r.History == nil || !r.History.Sample || r.History.Records != 1 || r.History.ObservedFrom == nil {
		t.Fatalf("result = %+v history = %+v", r.Summary, r.History)
	}
	notes := strings.Join(r.Notes, " ")
	if !strings.Contains(notes, "is a sample") || !strings.Contains(notes, "wildcard certificates that cover it are not included") {
		t.Fatalf("notes = %v", r.Notes)
	}
	if r.Issuances[1].Revocation.Status != "unknown" || !r.Issuances[1].Expired {
		t.Fatalf("the Validin-only issuance = %+v", r.Issuances[1])
	}
}

func TestValidinFailureDegradesButAnswers(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"example.com": 1}, remaining: -1}
	v := &fakeValidin{fail: &upstream.Error{Source: "Validin", Code: upstream.CodeUpstream, Status: 500, Detail: "refused"}, remaining: validin.Remaining{Daily: 10, Monthly: 50}}
	e, _ := newEngine(t, s, v)
	rep, _ := e.Lookup([]string{"example.com"}, Options{History: true})
	r := rep.Results[0]
	if !r.Degraded || r.Sources.Validin.State != StateFailed || r.Summary.Issuances != 1 || r.History != nil {
		t.Fatalf("result = %+v", r)
	}
	// And the failure is not cached: the next call asks again.
	v.fail = nil
	rep, _ = e.Lookup([]string{"example.com"}, Options{History: true})
	if rep.Results[0].Sources.Validin.FromCache || len(v.calls) != 2 {
		t.Fatalf("calls = %d", len(v.calls))
	}
}

func TestPacingKeepsUnderFiveASecond(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"a.example": 150, "b.example": 1}, remaining: -1}
	e, _ := newEngine(t, s, nil)
	_, _ = e.Lookup([]string{"a.example", "b.example"}, Options{})
	for i := 1; i < len(s.times); i++ {
		if gap := s.times[i].Sub(s.times[i-1]); gap < SSLMateInterval {
			t.Fatalf("requests %d and %d are %v apart", i-1, i, gap)
		}
	}
}

func TestScopeSeparatesCaches(t *testing.T) {
	s := &fakeSSLMate{count: map[string]int{"example.com": 1}, remaining: -1}
	e, _ := newEngine(t, s, nil)
	_, _ = e.Lookup([]string{"example.com"}, Options{})
	n := len(s.queries)
	e.SSLMateScope = "another key"
	_, _ = e.Lookup([]string{"example.com"}, Options{})
	if len(s.queries) == n {
		t.Fatal("an answer cached under another key or endpoint was served")
	}
}
