package validin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nlink-jp/cert-lookup/internal/guard"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
)

const fp1 = "d9fb9f93aa83e1cb8fea5239ea002222cd551ca7808a92a40bfa0dccb42cab13"

// Shaped like the Phase 0 capture (fictional names).
const history = `{"query_opts":{"limit":250,"wildcard":true,"type":"dom"},"query_key":"example.com","status":"finished",
"query_key":"example.com","records_returned":1,"limited":false,"records":{"ctstream":[
 {"key":"example.com","value_type":"JSON","first_seen":1791331200,"last_seen":1791331200,"value":{
  "links":["https://ct.example/get-entries?start=1&end=1"],"timestamp":"2026-10-07T03:45:16Z","indexes":[1],
  "update_type":"X509LogEntry","issuer_key_hash":null,"common_name":"Example.com",
  "cert_issuer":"/C=US/O=Amazon/CN=Amazon RSA 2048 M01","issuer":{"C":"US","O":"Amazon","CN":"Amazon RSA 2048 M01"},
  "not_before":"2026-05-07T00:00:00Z","not_after":"2026-11-20T23:59:59Z",
  "details":{"fingerprint":"a0ff","fingerprint_sha256":"` + fp1 + `","domains":["*.example.com"]},"type":null,"time":""}}
]}}`

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &Client{HTTP: &http.Client{CheckRedirect: guard.RefuseRedirects}, BaseURL: ts.URL, APIKey: "secret-key"}
}

func TestCertificatesSendsTheWindowAndParses(t *testing.T) {
	var got *http.Request
	c := server(t, func(w http.ResponseWriter, r *http.Request) { got = r; _, _ = w.Write([]byte(history)) })
	ans, err := c.Certificates("example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	q := got.URL.Query()
	if got.URL.Path != "/api/axon/domain/certificates/example.com" || q.Get("wildcard") != "true" || q.Get("limit") != "250" || q.Get("lookback") != "1095" || q.Get("time_format") != "unix" {
		t.Fatalf("request = %s?%s", got.URL.Path, got.URL.RawQuery)
	}
	if got.Header.Get("Authorization") != "Bearer secret-key" {
		t.Fatal("the key travels in the Authorization header")
	}
	if len(ans.Records) != 1 || ans.Limited {
		t.Fatalf("answer = %+v", ans)
	}
	r := ans.Records[0]
	if r.CommonName != "example.com" || strings.Join(r.Domains, ",") != "*.example.com" || r.FingerprintSHA256 != fp1 || r.Precert {
		t.Fatalf("record = %+v", r)
	}
	if r.Issuer != (Issuer{C: "US", O: "Amazon", CN: "Amazon RSA 2048 M01"}) || r.FirstSeen.Unix() != 1791331200 || r.LoggedAt.IsZero() {
		t.Fatalf("record = %+v", r)
	}
}

func TestSingleHostSendsWildcardFalse(t *testing.T) {
	var q string
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"status":"finished","records_returned":0,"limited":false,"records":{"ctstream":[]}}`))
	})
	ans, err := c.Certificates("www.example.com", false)
	if err != nil || len(ans.Records) != 0 || ans.Records == nil {
		t.Fatalf("ans=%+v err=%v", ans, err)
	}
	if !strings.Contains(q, "wildcard=false") {
		t.Fatalf("query = %s", q)
	}
}

// Measured: a wrong key gets 403 {"error":"Unauthorized user"}.
func TestForbiddenIsInvalidKeyWithoutUpstreamText(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"Unauthorized user secret-key"}`))
	})
	_, err := c.Certificates("example.com", false)
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Code != upstream.CodeInvalidAPIKey || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnfinishedOrMalformedIsAFailure(t *testing.T) {
	for name, body := range map[string]string{
		"not finished":    `{"status":"running","records":{"ctstream":[]}}`,
		"records missing": `{"status":"finished","records_returned":3}`,
		"not json":        `<html>`,
		"bad validity":    `{"status":"finished","records":{"ctstream":[{"value":{"not_before":"x","not_after":"y","details":{"fingerprint_sha256":"` + fp1 + `"}}}]}}`,
		"bad fingerprint": `{"status":"finished","records":{"ctstream":[{"value":{"not_before":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z","details":{"fingerprint_sha256":"ab"}}}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
			if _, err := c.Certificates("example.com", false); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestUsage(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/profile/usage" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"usage":{},"remaining":{"daily":8,"monthly":3,"next_daily_reset":1794096000,"next_monthly_reset":1796083200}}`))
	})
	r, err := c.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if r.Daily != 8 || r.Monthly != 3 || r.Smaller() != 3 || r.NextDailyReset.Unix() != 1794096000 {
		t.Fatalf("remaining = %+v", r)
	}
}

func TestUsageWithoutCountsIsAFailure(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"usage":{}}`)) })
	if _, err := c.Usage(); err == nil {
		t.Fatal("a usage answer without remaining counts must not read as zero or as plenty")
	}
}

// Review finding 8: absent times stay zero; a non-hex fingerprint is refused.
func TestAbsentTimesAndNonHexFingerprint(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"finished","records":{"ctstream":[{"value":{"not_before":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z","details":{"fingerprint_sha256":"` + fp1 + `"}}}]}}`))
	})
	ans, err := c.Certificates("example.com", false)
	if err != nil || !ans.Records[0].FirstSeen.IsZero() || !ans.Records[0].LastSeen.IsZero() {
		t.Fatalf("ans=%+v err=%v; an absent first_seen must stay the zero time, not 1970", ans, err)
	}
	c = server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"finished","records":{"ctstream":[{"value":{"not_before":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z","details":{"fingerprint_sha256":"` + strings.Repeat("zz", 32) + `"}}}]}}`))
	})
	if _, err := c.Certificates("example.com", false); err == nil {
		t.Fatal("a fingerprint that is not hex must be refused")
	}
}
