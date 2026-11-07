// Package sslmate is the client for the SSLMate CT Search API (v1), the source
// of currently valid certificates and their revocation status.
//
// What the API does, as documented and as measured in Phase 0:
//   - it returns only unexpired issuances, oldest-discovered first, 100 to a page;
//   - every page counts against the allowance, an empty one included;
//   - the end is an empty page (the documented signal; a short page is not
//     treated as the last);
//   - a public suffix (com, co.jp) is answered with an empty list, not an error;
//   - the remaining allowance is in X-Ratelimit-Limit / X-Ratelimit-Remaining,
//     per query kind (100 single-host, 10 full-domain on the free tier);
//   - a 429 carries Retry-After in seconds; the allowance refills gradually;
//   - the same issuance can appear under several ids (merged by tbs_sha256
//     downstream);
//   - the Link header's path drops /v1, so pages are built here from after=.
//
// The key travels only in the Authorization header, the client refuses
// redirects, and no error repeats the URL or upstream's message.
package sslmate

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
	"github.com/nlink-jp/cert-lookup/internal/upstream"
)

// DefaultBaseURL is the API's documented endpoint.
const DefaultBaseURL = "https://api.certspotter.com"

// PageSize is how many issuances a full page holds (measured).
const PageSize = 100

const source = "SSLMate"

// Client calls the API. HTTP must refuse redirects (guard.RefuseRedirects).
type Client struct {
	HTTP      *http.Client
	BaseURL   string // "" = DefaultBaseURL
	APIKey    string
	UserAgent string
}

// Query is one page request.
type Query struct {
	Domain            string
	IncludeSubdomains bool
	After             string // "" for the first page
}

// Issuer is the certificate authority as SSLMate describes it.
type Issuer struct {
	FriendlyName string   `json:"friendly_name,omitempty"`
	Name         string   `json:"name,omitempty"` // the issuer DN, RFC 2253-style
	CAADomains   []string `json:"caa_domains,omitempty"`
}

// Revocation is SSLMate's revocation detail. Every field is null when the
// status is unknown.
type Revocation struct {
	Time      *time.Time `json:"time"`
	Reason    *int       `json:"reason"`
	CheckedAt *time.Time `json:"checked_at"`
}

// Issuance is one issuance as returned (cleaned and capped).
type Issuance struct {
	ID         string      `json:"id"`
	TBSSHA256  string      `json:"tbs_sha256"`
	CertSHA256 string      `json:"cert_sha256"`
	DNSNames   []string    `json:"dns_names"`
	NotBefore  time.Time   `json:"not_before"`
	NotAfter   time.Time   `json:"not_after"`
	Revoked    *bool       `json:"revoked"`
	Revocation *Revocation `json:"revocation,omitempty"`
	Issuer     Issuer      `json:"issuer"`
}

// Allowance is the remaining-query state one response reported. Limit and
// Remaining are -1 when the header was absent: unknown is not exhausted.
type Allowance struct {
	Limit     int
	Remaining int
}

// Page is one page of issuances and the allowance after it.
type Page struct {
	Issuances []Issuance
	Allowance Allowance
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return DefaultBaseURL
}

// Fetch requests one page.
func (c *Client) Fetch(q Query) (*Page, error) {
	v := url.Values{}
	v.Set("domain", q.Domain)
	if q.IncludeSubdomains {
		v.Set("include_subdomains", "true")
	} else {
		// A single host also gets the wildcard certificates that cover it
		// (RFP §2).
		v.Set("match_wildcards", "true")
	}
	for _, e := range []string{"dns_names", "issuer", "issuer.caa_domains", "revocation"} {
		v.Add("expand", e)
	}
	if q.After != "" {
		v.Set("after", q.After)
	}
	req, err := http.NewRequest(http.MethodGet, c.base()+"/v1/issuances?"+v.Encode(), nil)
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
		return nil, &upstream.Error{Source: source, Code: code, Detail: "request failed: " + guard.Text(guard.ScrubURL(err).Error())}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := upstream.ReadBody(resp.Body)
	if err != nil {
		return nil, &upstream.Error{Source: source, Code: upstream.CodeUpstream, Status: resp.StatusCode, Detail: "reading the response failed: " + guard.Text(err.Error())}
	}
	allow := allowance(resp.Header)
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp, body)
	}
	var raw []wireIssuance
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, &upstream.Error{Source: source, Code: upstream.CodeUpstream, Status: resp.StatusCode, Detail: "the response is not the documented list of issuances"}
	}
	page := &Page{Allowance: allow, Issuances: make([]Issuance, 0, len(raw))}
	for i := range raw {
		is, err := raw[i].clean()
		if err != nil {
			return nil, &upstream.Error{Source: source, Code: upstream.CodeUpstream, Status: resp.StatusCode, Detail: "an issuance is malformed: " + err.Error()}
		}
		page.Issuances = append(page.Issuances, is)
	}
	return page, nil
}

// statusError turns a non-200 into our own message. SSLMate's error body is
// {"code","message"}; only the code is kept — the message for bad_credentials
// quotes the leading part of the key that was sent.
func statusError(resp *http.Response, body []byte) error {
	var eo struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &eo)
	e := &upstream.Error{Source: source, Status: resp.StatusCode, UpstreamCode: upstream.MachineCode(eo.Code), RetryAfter: retryAfter(resp.Header)}
	switch {
	case eo.Code == "bad_credentials" || eo.Code == "disabled_credentials" || eo.Code == "unauthorized" || resp.StatusCode == http.StatusUnauthorized:
		e.Code, e.Detail = upstream.CodeInvalidAPIKey, "the API key was not accepted (check [sslmate] api_key)"
	case eo.Code == "rate_limited" || resp.StatusCode == http.StatusTooManyRequests:
		e.Code, e.Detail = upstream.CodeRateLimited, "the query allowance is used up"
	case eo.Code == "timeout":
		e.Code, e.Detail = upstream.CodeTimeout, "the query ran past the plan's time limit"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		e.Code, e.Detail = upstream.CodeUpstream, "the API answered with a redirect, which is not followed"
	default:
		e.Code, e.Detail = upstream.CodeUpstream, "the API refused the request"
	}
	return e
}

func allowance(h http.Header) Allowance {
	return Allowance{Limit: headerInt(h, "X-Ratelimit-Limit"), Remaining: headerInt(h, "X-Ratelimit-Remaining")}
}

func headerInt(h http.Header, name string) int {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get(name)))
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// retryAfter reads Retry-After as seconds (the form SSLMate sends), 0 when
// absent or in another form.
func retryAfter(h http.Header) int {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After")))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// wireIssuance mirrors the JSON. Pointers tell absent from empty.
type wireIssuance struct {
	ID         string          `json:"id"`
	TBSSHA256  string          `json:"tbs_sha256"`
	CertSHA256 string          `json:"cert_sha256"`
	DNSNames   []string        `json:"dns_names"`
	NotBefore  string          `json:"not_before"`
	NotAfter   string          `json:"not_after"`
	Revoked    *bool           `json:"revoked"`
	Revocation *wireRevocation `json:"revocation"`
	Issuer     *struct {
		FriendlyName string   `json:"friendly_name"`
		Name         string   `json:"name"`
		CAADomains   []string `json:"caa_domains"`
	} `json:"issuer"`
}

type wireRevocation struct {
	Time      *string `json:"time"`
	Reason    *int    `json:"reason"`
	CheckedAt *string `json:"checked_at"`
}

func (w *wireIssuance) clean() (Issuance, error) {
	if w.ID == "" || !isHex64(w.TBSSHA256) {
		return Issuance{}, fmt.Errorf("missing id or tbs_sha256")
	}
	nb, err1 := time.Parse(time.RFC3339, w.NotBefore)
	na, err2 := time.Parse(time.RFC3339, w.NotAfter)
	if err1 != nil || err2 != nil {
		return Issuance{}, fmt.Errorf("validity is not RFC 3339")
	}
	is := Issuance{
		ID:        guard.Cap(w.ID, 40),
		TBSSHA256: strings.ToLower(w.TBSSHA256),
		NotBefore: nb.UTC(),
		NotAfter:  na.UTC(),
		Revoked:   w.Revoked,
		DNSNames:  CleanNames(w.DNSNames),
	}
	if isHex64(w.CertSHA256) {
		is.CertSHA256 = strings.ToLower(w.CertSHA256)
	}
	if w.Issuer != nil {
		is.Issuer = Issuer{FriendlyName: guard.Text(w.Issuer.FriendlyName), Name: guard.Text(w.Issuer.Name)}
		for i, d := range w.Issuer.CAADomains {
			if i == 20 {
				break
			}
			if d = guard.Cap(d, guard.MaxDNSName); d != "" {
				is.Issuer.CAADomains = append(is.Issuer.CAADomains, d)
			}
		}
	}
	if w.Revocation != nil {
		is.Revocation = &Revocation{Reason: w.Revocation.Reason, Time: parseTime(w.Revocation.Time), CheckedAt: parseTime(w.Revocation.CheckedAt)}
	}
	return is, nil
}

// CleanNames cleans, lower-cases, caps and de-duplicates certificate names.
// Every name is kept here — merging compares whole name sets — and the output
// layer caps how many are shown (RFP §3).
func CleanNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.ToLower(guard.Cap(n, guard.MaxDNSName))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func parseTime(s *string) *time.Time {
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
