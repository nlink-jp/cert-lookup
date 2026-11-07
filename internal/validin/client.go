// Package validin is the client for Validin's certificate-history endpoint and
// its usage endpoint (Community tier).
//
// What the API does, as measured in Phase 0 (its response shape is not
// documented beyond an empty object):
//   - the host is app.validin.com (api.validin.com does not resolve);
//   - without a window only a recent subset comes back, so a window is always
//     sent (lookback=1095); even with one, large domains miss whole months and
//     `limited` still says false — the history is a sample, never complete;
//   - a single-host query returns no covering wildcard certificates;
//   - one issuance comes back once per CT log and once more as a
//     precertificate; there is no serial number;
//   - a zero-record answer is status "finished" and still spends a query;
//   - a wrong key gets 403 {"error":"Unauthorized user"} and spends nothing;
//   - /api/profile/usage spends nothing.
//
// The key travels only in the Authorization header, the client refuses
// redirects, and no error repeats the URL or upstream's message.
package validin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/guard"
	"github.com/nlink-jp/cert-lookup/internal/sslmate"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
)

// DefaultBaseURL is the measured endpoint.
const DefaultBaseURL = "https://app.validin.com"

// Lookback is the window sent with every query, in days (RFP §2: three years,
// aimed at the past; current certificates come from SSLMate).
const Lookback = 1095

// Limit is the most records the Community tier returns per query.
const Limit = 250

const source = "Validin"

// Client calls the API. HTTP must refuse redirects (guard.RefuseRedirects).
type Client struct {
	HTTP      *http.Client
	BaseURL   string // "" = DefaultBaseURL
	APIKey    string
	UserAgent string
}

// Issuer is the issuer DN as components.
type Issuer struct {
	C  string `json:"c,omitempty"`
	O  string `json:"o,omitempty"`
	CN string `json:"cn,omitempty"`
}

// Record is one CT log observation of a certificate or precertificate.
type Record struct {
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	LoggedAt          time.Time `json:"logged_at,omitzero"` // the CT entry's timestamp
	CommonName        string    `json:"common_name,omitempty"`
	Domains           []string  `json:"domains"`
	Issuer            Issuer    `json:"issuer"`
	IssuerDN          string    `json:"issuer_dn,omitempty"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Precert           bool      `json:"precert,omitempty"`
}

// Answer is one certificate-history query.
type Answer struct {
	Records []Record `json:"records"`
	// Limited is what Validin said; false does not mean complete (Phase 0).
	Limited bool `json:"limited"`
}

// Remaining is the account's remaining queries.
type Remaining struct {
	Daily            int       `json:"daily"`
	Monthly          int       `json:"monthly"`
	NextDailyReset   time.Time `json:"next_daily_reset,omitzero"`
	NextMonthlyReset time.Time `json:"next_monthly_reset,omitzero"`
}

// Smaller is the binding remainder: the lesser of daily and monthly.
func (r Remaining) Smaller() int { return min(r.Daily, r.Monthly) }

func (c *Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return DefaultBaseURL
}

// Certificates asks for a domain's certificate history. subdomains maps to
// Validin's wildcard ("Include Child Labels").
func (c *Client) Certificates(domain string, subdomains bool) (*Answer, error) {
	v := url.Values{}
	v.Set("wildcard", strconv.FormatBool(subdomains))
	v.Set("limit", strconv.Itoa(Limit))
	v.Set("lookback", strconv.Itoa(Lookback))
	v.Set("time_format", "unix")
	body, err := c.get("/api/axon/domain/certificates/"+url.PathEscape(domain)+"?"+v.Encode(), "the certificate history")
	if err != nil {
		return nil, err
	}
	var w wireAnswer
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, malformed("the response is not the measured certificate-history object")
	}
	if w.Status != "finished" {
		return nil, malformed("the query did not finish (status " + strconv.Quote(guard.Cap(w.Status, 20)) + ")")
	}
	if w.Records == nil {
		if w.RecordsReturned != 0 {
			return nil, malformed("records are missing although some were returned")
		}
		return &Answer{Limited: w.Limited, Records: []Record{}}, nil
	}
	ans := &Answer{Limited: w.Limited, Records: make([]Record, 0, len(w.Records.CTStream))}
	for i := range w.Records.CTStream {
		r, err := w.Records.CTStream[i].clean()
		if err != nil {
			return nil, malformed("a record is malformed: " + err.Error())
		}
		ans.Records = append(ans.Records, r)
	}
	return ans, nil
}

// Usage reads the account's remaining queries; it spends none (measured).
func (c *Client) Usage() (*Remaining, error) {
	body, err := c.get("/api/profile/usage", "the usage")
	if err != nil {
		return nil, err
	}
	var w struct {
		Remaining *struct {
			Daily            *int  `json:"daily"`
			Monthly          *int  `json:"monthly"`
			NextDailyReset   int64 `json:"next_daily_reset"`
			NextMonthlyReset int64 `json:"next_monthly_reset"`
		} `json:"remaining"`
	}
	if err := json.Unmarshal(body, &w); err != nil || w.Remaining == nil || w.Remaining.Daily == nil || w.Remaining.Monthly == nil {
		return nil, malformed("the usage response has no remaining daily and monthly counts")
	}
	r := &Remaining{Daily: *w.Remaining.Daily, Monthly: *w.Remaining.Monthly}
	if w.Remaining.NextDailyReset > 0 {
		r.NextDailyReset = time.Unix(w.Remaining.NextDailyReset, 0).UTC()
	}
	if w.Remaining.NextMonthlyReset > 0 {
		r.NextMonthlyReset = time.Unix(w.Remaining.NextMonthlyReset, 0).UTC()
	}
	return r, nil
}

func malformed(detail string) error {
	return &upstream.Error{Source: source, Code: upstream.CodeUpstream, Detail: detail}
}

func (c *Client) get(pathQuery, what string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.base()+pathQuery, nil)
	if err != nil {
		return nil, &upstream.Error{Source: source, Code: upstream.CodeUpstream, Detail: "could not build the request"}
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		code := upstream.CodeUpstream
		var ne interface{ Timeout() bool }
		if errors.As(err, &ne) && ne.Timeout() {
			code = upstream.CodeTimeout
		}
		return nil, &upstream.Error{Source: source, Code: code, Detail: "request for " + what + " failed: " + guard.Text(guard.ScrubURL(err).Error())}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := upstream.ReadBody(resp.Body)
	if err != nil {
		return nil, &upstream.Error{Source: source, Code: upstream.CodeUpstream, Status: resp.StatusCode, Detail: "reading " + what + " failed: " + guard.Text(err.Error())}
	}
	if resp.StatusCode == http.StatusOK {
		return body, nil
	}
	// Validin's error body is free text ({"error":"Unauthorized user"});
	// none of it is passed through.
	e := &upstream.Error{Source: source, Status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		e.Code, e.Detail = upstream.CodeInvalidAPIKey, "the API key was not accepted (check [validin] api_key)"
	case resp.StatusCode == http.StatusTooManyRequests:
		e.Code, e.Detail = upstream.CodeRateLimited, "the query allowance is used up"
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
			e.RetryAfter = n
		}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		e.Code, e.Detail = upstream.CodeUpstream, "the API answered with a redirect, which is not followed"
	default:
		e.Code, e.Detail = upstream.CodeUpstream, "the API refused the request for "+what
	}
	return nil, e
}

type wireAnswer struct {
	Status          string `json:"status"`
	RecordsReturned int    `json:"records_returned"`
	Limited         bool   `json:"limited"`
	Records         *struct {
		CTStream []wireRecord `json:"ctstream"`
	} `json:"records"`
}

type wireRecord struct {
	FirstSeen int64 `json:"first_seen"`
	LastSeen  int64 `json:"last_seen"`
	Value     struct {
		Timestamp  string `json:"timestamp"`
		UpdateType string `json:"update_type"`
		CommonName string `json:"common_name"`
		CertIssuer string `json:"cert_issuer"`
		Issuer     struct {
			C  string `json:"C"`
			O  string `json:"O"`
			CN string `json:"CN"`
		} `json:"issuer"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
		Details   struct {
			FingerprintSHA256 string   `json:"fingerprint_sha256"`
			Domains           []string `json:"domains"`
		} `json:"details"`
	} `json:"value"`
}

// unixOrZero reads a unix time, keeping an absent (0) one as the zero time
// rather than 1970-01-01.
func unixOrZero(n int64) time.Time {
	if n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (w *wireRecord) clean() (Record, error) {
	v := &w.Value
	nb, err1 := time.Parse(time.RFC3339, v.NotBefore)
	na, err2 := time.Parse(time.RFC3339, v.NotAfter)
	if err1 != nil || err2 != nil {
		return Record{}, fmt.Errorf("validity is not RFC 3339")
	}
	fp := strings.ToLower(v.Details.FingerprintSHA256)
	if !isHex64(fp) {
		return Record{}, fmt.Errorf("fingerprint_sha256 is not a SHA-256")
	}
	r := Record{
		FirstSeen:         unixOrZero(w.FirstSeen),
		LastSeen:          unixOrZero(w.LastSeen),
		CommonName:        strings.ToLower(guard.Cap(v.CommonName, guard.MaxDNSName)),
		Domains:           sslmate.CleanNames(v.Details.Domains),
		Issuer:            Issuer{C: guard.Text(v.Issuer.C), O: guard.Text(v.Issuer.O), CN: guard.Text(v.Issuer.CN)},
		IssuerDN:          guard.Text(v.CertIssuer),
		NotBefore:         nb.UTC(),
		NotAfter:          na.UTC(),
		FingerprintSHA256: fp,
		Precert:           v.UpdateType == "PreCertEntry",
	}
	if t, err := time.Parse(time.RFC3339, v.Timestamp); err == nil {
		r.LoggedAt = t.UTC()
	}
	return r, nil
}
