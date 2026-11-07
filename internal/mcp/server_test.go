package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/config"
	"github.com/nlink-jp/cert-lookup/internal/engine"
	"github.com/nlink-jp/cert-lookup/internal/issuance"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

func testConfig(sslmateKey, validinKey string) *config.Config {
	return &config.Config{SSLMateKey: sslmateKey, ValidinKey: validinKey, CacheDir: "/nonexistent/cert-lookup-test-cache", Timeout: time.Second}
}

// fakeEngine records calls and answers each domain with n issuances.
type fakeEngine struct {
	calls   [][]string
	opts    []engine.Options
	n       int
	names   int // names per issuance
	err     error
	allowed map[string]engine.Observed
}

func (f *fakeEngine) Lookup(domains []string, o engine.Options) (*engine.Report, error) {
	f.calls = append(f.calls, domains)
	f.opts = append(f.opts, o)
	if f.err != nil {
		return nil, f.err
	}
	rep := &engine.Report{}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for di, d := range domains {
		r := engine.DomainResult{Domain: d, Issuances: []issuance.Issuance{}}
		for i := 0; i < f.n; i++ {
			names := []string{d}
			for k := 0; k < f.names; k++ {
				names = append(names, fmt.Sprintf("n%03d.%s", k, d))
			}
			r.Issuances = append(r.Issuances, issuance.Issuance{
				Names: names, NamesTotal: len(names),
				Issuer:     issuance.Issuer{Name: "Example CA", DN: "C=US, O=Example CA, CN=R1"},
				NotBefore:  base.Add(time.Duration(di*1000+i) * time.Hour),
				NotAfter:   base.Add(9000 * time.Hour),
				Revocation: issuance.Revocation{Status: issuance.NotRevoked},
				CertSHA256: []string{strings.Repeat("a", 64)},
				SeenBy:     []string{issuance.SourceSSLMate},
			})
		}
		r.Summary = issuance.Summary{Issuances: f.n, Issuers: []string{"Example CA"}, IssuersTotal: 1, NamesOutside: []string{}}
		r.Sources.SSLMate = engine.SourceState{State: engine.StateOK}
		r.Sources.Validin = engine.SourceState{State: engine.StateNotRequested}
		rep.Results = append(rep.Results, r)
	}
	return rep, nil
}

func (f *fakeEngine) Allowances() map[string]engine.Observed { return f.allowed }

// serve feeds newline-delimited JSON-RPC requests through the server and
// returns the decoded responses.
func serve(t *testing.T, cfg *config.Config, lines ...string) []map[string]any {
	t.Helper()
	return serveWith(t, Options{Config: cfg, Engine: &fakeEngine{n: 1}, Version: "test"}, lines...)
}

func serveWith(t *testing.T, o Options, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(o, strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, m)
	}
	return resps
}

func callTool(name, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args)
}

// toolText extracts the text payload and isError flag of a tools/call response.
func toolText(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	return text, isErr
}

func errorCode(t *testing.T, text string) string {
	t.Helper()
	var e struct{ Code, Message string }
	if err := json.Unmarshal([]byte(text), &e); err != nil {
		t.Fatalf("tool error is not structured JSON: %v (%s)", err, text)
	}
	return e.Code
}

func TestInitializeEchoesProtocolAndNamesTheServer(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	res := resps[0]["result"].(map[string]any)
	if res["protocolVersion"] != "2024-11-05" || res["serverInfo"].(map[string]any)["name"] != "cert-lookup" {
		t.Fatalf("initialize = %v", res)
	}
	if !strings.Contains(res["instructions"].(string), "get_usage") {
		t.Fatal("instructions must point at get_usage")
	}
}

func TestToolsList(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var names []string
	for _, x := range resps[0]["result"].(map[string]any)["tools"].([]any) {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "lookup_certs,get_usage,cache_status" {
		t.Fatalf("tools = %v", names)
	}
}

func TestGetUsageReturnsTheManual(t *testing.T) {
	text, isErr := toolText(t, serve(t, testConfig("", ""), callTool(ToolGetUsage, `{}`))[0])
	if isErr || !strings.Contains(text, "cert-lookup MCP server") {
		t.Fatalf("get_usage: isErr=%v", isErr)
	}
}

func TestUnknownToolIsAStructuredError(t *testing.T) {
	text, isErr := toolText(t, serve(t, testConfig("", ""), callTool("check_ip", `{"ips":["x"]}`))[0])
	if !isErr || errorCode(t, text) != CodeUnknownTool {
		t.Fatalf("unknown tool: isErr=%v %s", isErr, text)
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	resps := serve(t, testConfig("", ""),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if len(resps) != 1 {
		t.Fatalf("responses = %d, want only the ping reply", len(resps))
	}
}

func TestUnknownMethodIsRPCError(t *testing.T) {
	if resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`); resps[0]["error"] == nil {
		t.Fatalf("want a JSON-RPC error, got %v", resps[0])
	}
}

func TestMalformedJSONReportsParseErrorAndStops(t *testing.T) {
	if resps := serve(t, testConfig("", ""), `{not json`); len(resps) != 1 || resps[0]["error"] == nil {
		t.Fatalf("want a single parse-error response, got %v", resps)
	}
}

func TestLookupAnswersThroughTheEngine(t *testing.T) {
	eng := &fakeEngine{n: 2}
	resps := serveWith(t, Options{Config: testConfig("sk", "vk"), Engine: eng, Version: "t"},
		callTool(ToolLookupCerts, `{"domains":["Example.com","example.com.","www.example.org"],"subdomains":true,"history":true,"refresh":true}`))
	text, isErr := toolText(t, resps[0])
	if isErr {
		t.Fatal(text)
	}
	if len(eng.calls) != 1 || strings.Join(eng.calls[0], ",") != "example.com,www.example.org" {
		t.Fatalf("engine got %v; want canonical, de-duplicated names", eng.calls)
	}
	if o := eng.opts[0]; !o.Subdomains || !o.History || !o.Refresh {
		t.Fatalf("options = %+v", o)
	}
	var r lookupResult
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 2 || r.Provenance == "" || r.OmittedTotal != 0 {
		t.Fatalf("result = %+v", r)
	}
	if strings.Contains(text, "\n") {
		t.Fatal("the result should be compact JSON (it counts against the budget)")
	}
}

func TestLookupRefusesBeforeAnythingIsSent(t *testing.T) {
	for args, code := range map[string]string{
		`{}`:                                  CodeInvalidInput,
		`{"domains":[]}`:                      CodeInvalidInput,
		`{"domains":"example.com"}`:           CodeInvalidInput,
		`{"domains":["https://example.com"]}`: CodeInvalidDomain,
		`{"domains":["例え.jp"]}`:               CodeInvalidDomain,
		`{"domains":["192.0.2.1"]}`:           CodeInvalidDomain,
		`{"domains":["*.example.com"]}`:       CodeInvalidDomain,
	} {
		eng := &fakeEngine{n: 1}
		text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("sk", ""), Engine: eng}, callTool(ToolLookupCerts, args))[0])
		if !isErr || errorCode(t, text) != code || len(eng.calls) != 0 {
			t.Errorf("%s: isErr=%v code=%s calls=%d; want %s and nothing sent", args, isErr, text, len(eng.calls), code)
		}
	}
}

func TestTooManyDomains(t *testing.T) {
	var ds []string
	for i := 0; i < MaxPerCall+1; i++ {
		ds = append(ds, fmt.Sprintf("%q", fmt.Sprintf("d%d.example.com", i)))
	}
	text, isErr := toolText(t, serve(t, testConfig("sk", ""), callTool(ToolLookupCerts, `{"domains":[`+strings.Join(ds, ",")+`]}`))[0])
	if !isErr || errorCode(t, text) != CodeTooManyDomains {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
}

func TestLookupWithoutSSLMateKeyIsNoAPIKey(t *testing.T) {
	eng := &fakeEngine{n: 1}
	text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("", "vk"), Engine: eng}, callTool(ToolLookupCerts, `{"domains":["example.com"]}`))[0])
	if !isErr || errorCode(t, text) != CodeNoAPIKey || len(eng.calls) != 0 {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
}

// The engine's whole-call refusals pass through with their own code.
func TestCallErrorsKeepTheirCode(t *testing.T) {
	for _, code := range []string{CodeHistoryUnavailable, CodeQuotaExhausted, CodeInvalidAPIKey} {
		eng := &fakeEngine{err: &engine.CallError{Code: code, Message: "m"}}
		text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("sk", "vk"), Engine: eng}, callTool(ToolLookupCerts, `{"domains":["example.com"],"history":true}`))[0])
		if !isErr || errorCode(t, text) != code {
			t.Errorf("code %s: isErr=%v %s", code, isErr, text)
		}
	}
	eng := &fakeEngine{err: errors.New("unexpected")}
	text, _ := toolText(t, serveWith(t, Options{Config: testConfig("sk", ""), Engine: eng}, callTool(ToolLookupCerts, `{"domains":["example.com"]}`))[0])
	if errorCode(t, text) != CodeInternal {
		t.Fatalf("an unexpected error is internal_error: %s", text)
	}
}

// A large domain (measured: one SSLMate page of 100 issuances is 540-608 KB)
// must come back under the ceiling, oldest issuances dropped first across
// every domain, counted per domain, with the summaries whole.
func TestResultIsCappedOldestFirst(t *testing.T) {
	eng := &fakeEngine{n: 300, names: 40}
	text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("sk", ""), Engine: eng},
		callTool(ToolLookupCerts, `{"domains":["a.example","b.example"]}`))[0])
	if isErr {
		t.Fatal(text)
	}
	wire, _ := json.Marshal(text)
	if len(wire) > maxResultBytes {
		t.Fatalf("result is %d bytes on the wire; ceiling %d", len(wire), maxResultBytes)
	}
	var r lookupResult
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		t.Fatal(err)
	}
	a, b := r.Results[0], r.Results[1]
	if r.OmittedTotal == 0 || a.Omitted+b.Omitted != r.OmittedTotal || a.Omitted+len(a.Issuances) != 300 {
		t.Fatalf("omitted a=%d b=%d total=%d kept a=%d b=%d", a.Omitted, b.Omitted, r.OmittedTotal, len(a.Issuances), len(b.Issuances))
	}
	// a's issuances are all older than b's in the fake, so a loses first.
	if a.Omitted <= b.Omitted {
		t.Fatalf("the oldest must go first: a omitted %d, b omitted %d", a.Omitted, b.Omitted)
	}
	if a.Summary.Issuances != 300 {
		t.Fatal("the summary must still count every issuance")
	}
	// What is kept of a domain is its newest: the fake's issuance i of a.example
	// is i hours after base, so after dropping the oldest, none older than
	// base + omitted hours may remain.
	cut := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(a.Omitted) * time.Hour)
	for _, is := range a.Issuances {
		if is.NotBefore.Before(cut) {
			t.Fatalf("an older issuance (%v) was kept while a newer one was dropped (cut %v)", is.NotBefore, cut)
		}
	}
}

func TestSmallResultsAreNotCut(t *testing.T) {
	eng := &fakeEngine{n: 20, names: 2}
	text, _ := toolText(t, serveWith(t, Options{Config: testConfig("sk", ""), Engine: eng}, callTool(ToolLookupCerts, `{"domains":["example.com"]}`))[0])
	var r lookupResult
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		t.Fatal(err)
	}
	if r.OmittedTotal != 0 || len(r.Results[0].Issuances) != 20 {
		t.Fatalf("omitted %d kept %d", r.OmittedTotal, len(r.Results[0].Issuances))
	}
}

// The ceiling is measured on the text as it travels, escaped a second time:
// names full of characters JSON escapes take more room on the wire.
func TestCeilingMeasuresTheEscapedText(t *testing.T) {
	r := &lookupResult{Report: &engine.Report{Results: []engine.DomainResult{{Domain: "example.com"}}}}
	for i := 0; i < 400; i++ {
		r.Results[0].Issuances = append(r.Results[0].Issuances, issuance.Issuance{
			Names:     []string{strings.Repeat(`"\`, 100)},
			NotBefore: time.Unix(int64(i), 0),
		})
	}
	res := capResult(r)
	wire, _ := json.Marshal(res.Content[0].Text)
	if len(wire) > maxResultBytes {
		t.Fatalf("wire %d > %d", len(wire), maxResultBytes)
	}
}

func TestCacheStatusWithoutKeys(t *testing.T) {
	text, isErr := toolText(t, serve(t, testConfig("", ""), callTool(ToolCacheStatus, `{}`))[0])
	if isErr || !strings.Contains(text, `"sslmate": false`) || !strings.Contains(text, "no Validin key") {
		t.Fatalf("cache_status: isErr=%v %s", isErr, text)
	}
}

func TestCacheStatusReportsAllowanceQuotaAndNeverAKey(t *testing.T) {
	seen := time.Date(2026, 11, 7, 4, 0, 0, 0, time.UTC)
	eng := &fakeEngine{allowed: map[string]engine.Observed{engine.KindHost: {Limit: 100, Remaining: 94, ObservedAt: seen}}}
	o := Options{Config: testConfig("sk-secret", "vk-secret"), Engine: eng, ValidinQuota: func() (*validin.Remaining, error) {
		return &validin.Remaining{Daily: 2, Monthly: 43}, nil
	}}
	text, isErr := toolText(t, serveWith(t, o, callTool(ToolCacheStatus, `null`))[0])
	if isErr || strings.Contains(text, "secret") {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
	for _, want := range []string{`"single_host"`, `"remaining": 94`, `"observed_at": "2026-11-07T04:00:00Z"`, `"daily": 2`, `"monthly": 43`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}
	o.ValidinQuota = func() (*validin.Remaining, error) { return nil, errors.New("Validin: refused") }
	text, isErr = toolText(t, serveWith(t, o, callTool(ToolCacheStatus, `{}`))[0])
	if isErr || !strings.Contains(text, "Validin: refused") {
		t.Fatalf("a failed quota read is reported inside the status: %s", text)
	}
}

// Review finding 9: a very long list is too_many_domains, not invalid_domain.
func TestVeryLongListIsTooMany(t *testing.T) {
	var ds []string
	for i := 0; i < 10*MaxPerCall+1; i++ {
		ds = append(ds, `"example.com"`)
	}
	text, isErr := toolText(t, serve(t, testConfig("sk", ""), callTool(ToolLookupCerts, `{"domains":[`+strings.Join(ds, ",")+`]}`))[0])
	if !isErr || errorCode(t, text) != CodeTooManyDomains {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
}

// Review finding 10: with no issuances left to drop, the summaries' lists go;
// the result never crosses the ceiling, with room left for the envelope.
func TestCapHoldsEvenForHugeSummaries(t *testing.T) {
	r := &lookupResult{Report: &engine.Report{}}
	for d := 0; d < 20; d++ {
		var names []string
		for i := 0; i < 100; i++ {
			names = append(names, fmt.Sprintf("%0250d.example", i))
		}
		r.Results = append(r.Results, engine.DomainResult{Domain: fmt.Sprintf("d%d.example", d), Issuances: []issuance.Issuance{},
			Summary: issuance.Summary{NamesOutside: names, NamesOutsideTotal: 100, Issuers: []string{"CA"}, IssuersTotal: 1}})
	}
	res := capResult(r)
	wire, _ := json.Marshal(res.Content[0].Text)
	if len(wire) > maxResultBytes-envelopeBytes {
		t.Fatalf("wire %d over the ceiling", len(wire))
	}
	var out lookupResult
	if res.IsError || json.Unmarshal([]byte(res.Content[0].Text), &out) != nil || out.Results[0].Summary.NamesOutsideTotal != 100 || len(out.Results[0].Summary.NamesOutside) != 0 {
		t.Fatalf("lists must be emptied with their totals kept: %.300s", res.Content[0].Text)
	}
}
