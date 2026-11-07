// Package guard holds the rules every upstream client follows: third-party
// text is cleaned and capped before it can reach a terminal or an MCP client,
// the HTTP client that carries an API key never follows a redirect, and a
// network error never quotes the request URL.
package guard

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// Clean strips control (Cc) and format (Cf) characters from third-party text —
// terminal escapes, bidi overrides, zero-width characters — and trims the
// result. Certificate names and issuers are written by certificate authorities
// and applicants; the words survive as claims, the control does not.
func Clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s))
}

// Caps on third-party strings (RFP §3). Upstream sets no limit, and every
// result has to fit a client's budget.
const (
	// MaxDNSName is the longest a DNS name can be (RFC 1035).
	MaxDNSName = 253
	// MaxText caps every other third-party string: issuer names, DN components,
	// revocation reasons.
	MaxText = 200
)

// Cap cleans a third-party string and caps it at n characters, marking a cut
// with an ellipsis.
func Cap(s string, n int) string {
	s = Clean(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// Text cleans a third-party string and caps it at MaxText characters.
func Text(s string) string { return Cap(s, MaxText) }

// RefuseRedirects is the CheckRedirect for every http.Client that carries a
// key. Go strips Authorization on a cross-host redirect, but a redirect is
// still a request to a host nobody configured, possibly over plain HTTP.
// Neither API redirects; a 3xx is reported instead.
func RefuseRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ScrubURL returns err without the request URL: Go's *url.Error formats as
// `Op "URL": Err`. Neither key travels in a URL here, but the URL carries the
// domain under investigation and the base URL from the config, and an error
// message is not where either belongs.
func ScrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return errors.New(ue.Op + ": " + ue.Err.Error())
	}
	return err
}
