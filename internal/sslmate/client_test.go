package sslmate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nlink-jp/cert-lookup/internal/guard"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
)

const tbs1 = "3fb2c998f9839fc264233db73cb496a4fbbe32b6b563e190644e23cb76651ec7"
const cert1 = "d9fb9f93aa83e1cb8fea5239ea002222cd551ca7808a92a40bfa0dccb42cab13"

// A page shaped like the Phase 0 capture (fictional names).
const onePage = `[
 {"id":"14798080508","tbs_sha256":"` + tbs1 + `","cert_sha256":"` + cert1 + `",
  "dns_names":["*.example.com","EXAMPLE.com"],"pubkey_sha256":"a1",
  "issuer":{"friendly_name":"Amazon Trust Services","caa_domains":["amazon.com","amazontrust.com"],"name":"C=US, O=Amazon, CN=Amazon RSA 2048 M01"},
  "not_before":"2026-05-07T00:00:00Z","not_after":"2026-11-20T23:59:59Z","revoked":false,
  "revocation":{"time":null,"reason":null,"checked_at":"2026-11-06T01:02:03Z"}},
 {"id":"17632760360","tbs_sha256":"` + tbs1 + `","cert_sha256":"` + cert1 + `",
  "dns_names":["*.example.com","example.com"],
  "issuer":{"friendly_name":"Amazon Trust Services","name":"C=US, O=Amazon, CN=Amazon RSA 2048 M01"},
  "not_before":"2026-05-07T00:00:00Z","not_after":"2026-11-20T23:59:59Z","revoked":null}
]`

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &Client{HTTP: &http.Client{CheckRedirect: guard.RefuseRedirects}, BaseURL: ts.URL, APIKey: "secret-key", UserAgent: "cert-lookup/test"}
}

func TestFetchBuildsTheDocumentedQuery(t *testing.T) {
	var got *http.Request
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("X-Ratelimit-Limit", "100")
		w.Header().Set("X-Ratelimit-Remaining", "97")
		_, _ = w.Write([]byte(onePage))
	})
	p, err := c.Fetch(Query{Domain: "www.example.com", After: "123"})
	if err != nil {
		t.Fatal(err)
	}
	q := got.URL.Query()
	if got.URL.Path != "/v1/issuances" || q.Get("domain") != "www.example.com" || q.Get("match_wildcards") != "true" || q.Get("include_subdomains") != "" || q.Get("after") != "123" {
		t.Fatalf("query = %s %s", got.URL.Path, got.URL.RawQuery)
	}
	if strings.Join(q["expand"], ",") != "dns_names,issuer,issuer.caa_domains,revocation" {
		t.Fatalf("expand = %v", q["expand"])
	}
	if got.Header.Get("Authorization") != "Bearer secret-key" || strings.Contains(got.URL.RawQuery, "secret-key") {
		t.Fatal("the key travels in the Authorization header only")
	}
	if p.Allowance != (Allowance{Limit: 100, Remaining: 97}) {
		t.Fatalf("allowance = %+v", p.Allowance)
	}
	if len(p.Issuances) != 2 {
		t.Fatalf("issuances = %d", len(p.Issuances))
	}
	is := p.Issuances[0]
	if is.TBSSHA256 != tbs1 || is.CertSHA256 != cert1 || strings.Join(is.DNSNames, ",") != "*.example.com,example.com" {
		t.Fatalf("issuance = %+v", is)
	}
	if is.Issuer.FriendlyName != "Amazon Trust Services" || len(is.Issuer.CAADomains) != 2 || is.Revoked == nil || *is.Revoked {
		t.Fatalf("issuer/revoked = %+v %v", is.Issuer, is.Revoked)
	}
	if is.Revocation == nil || is.Revocation.CheckedAt == nil || is.Revocation.Time != nil {
		t.Fatalf("revocation = %+v", is.Revocation)
	}
	if p.Issuances[1].Revoked != nil {
		t.Fatal("revoked:null must stay unknown, not false")
	}
}

func TestSubdomainQueryDropsMatchWildcards(t *testing.T) {
	var q string
	c := server(t, func(w http.ResponseWriter, r *http.Request) { q = r.URL.RawQuery; _, _ = w.Write([]byte("[]")) })
	if _, err := c.Fetch(Query{Domain: "example.com", IncludeSubdomains: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, "include_subdomains=true") || strings.Contains(q, "match_wildcards") {
		t.Fatalf("query = %s", q)
	}
}

// Missing rate-limit headers are unknown, never "zero left".
func TestAllowanceUnknownIsNotExhausted(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("[]")) })
	p, err := c.Fetch(Query{Domain: "co.jp"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowance != (Allowance{Limit: -1, Remaining: -1}) || len(p.Issuances) != 0 {
		t.Fatalf("page = %+v", p)
	}
}

// Measured in Phase 0: a wrong key gets 401 bad_credentials with a message
// that quotes the leading part of the key. Only our own words come out.
func TestBadCredentialsNeverEchoesTheMessage(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"bad_credentials","message":"The provided API key (secret_********) is not recognized."}`))
	})
	_, err := c.Fetch(Query{Domain: "example.com"})
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Code != upstream.CodeInvalidAPIKey || ue.UpstreamCode != "bad_credentials" {
		t.Fatalf("err = %#v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "not recognized") {
		t.Fatalf("upstream's message leaked: %v", err)
	}
}

// Measured: the 11th subdomain query got 429 rate_limited, Retry-After: 264.
func TestRateLimitedCarriesRetryAfter(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "264")
		w.Header().Set("X-Ratelimit-Remaining", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":"rate_limited","message":"You have exceeded your domain search quota"}`))
	})
	_, err := c.Fetch(Query{Domain: "example.com", IncludeSubdomains: true})
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Code != upstream.CodeRateLimited || ue.RetryAfter != 264 {
		t.Fatalf("err = %#v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	})
	_, err := c.Fetch(Query{Domain: "example.com"})
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Status != http.StatusFound || !strings.Contains(ue.Detail, "redirect") {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedResponsesAreFailures(t *testing.T) {
	for name, body := range map[string]string{
		"not a list":   `{"issuances":[]}`,
		"html":         `<html>`,
		"missing tbs":  `[{"id":"1","not_before":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z"}]`,
		"bad validity": `[{"id":"1","tbs_sha256":"` + tbs1 + `","not_before":"yesterday","not_after":"2026-02-01T00:00:00Z"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
			if _, err := c.Fetch(Query{Domain: "example.com"}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// The URL carries the domain under investigation; a network error must not
// repeat it.
func TestNetworkErrorOmitsTheURL(t *testing.T) {
	c := &Client{HTTP: &http.Client{}, BaseURL: "http://127.0.0.1:1", APIKey: "k"}
	_, err := c.Fetch(Query{Domain: "investigated.example"})
	if err == nil {
		t.Skip("something listens on 127.0.0.1:1")
	}
	if strings.Contains(err.Error(), "investigated.example") || strings.Contains(err.Error(), "127.0.0.1:1/v1") {
		t.Fatalf("error repeats the URL: %v", err)
	}
}

func TestThirdPartyTextIsCleaned(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"1","tbs_sha256":"` + tbs1 + `","dns_names":["evil\u001b[2J.example.com","a.example.com","A.example.com"],
		"issuer":{"friendly_name":"Bad\u202eCA","name":"` + strings.Repeat("x", 500) + `"},
		"not_before":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z","revoked":false}]`))
	})
	p, err := c.Fetch(Query{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	is := p.Issuances[0]
	if is.DNSNames[0] != "evil[2j.example.com" || len(is.DNSNames) != 2 {
		t.Fatalf("names = %q (cleaned, lower-cased, de-duplicated)", is.DNSNames)
	}
	if is.Issuer.FriendlyName != "BadCA" || len([]rune(is.Issuer.Name)) != guard.MaxText+1 {
		t.Fatalf("issuer = %q / %d runes", is.Issuer.FriendlyName, len([]rune(is.Issuer.Name)))
	}
}
